import logging
import pandas as pd

import dataiku
from dataiku.runnables import ResultTable
import datetime
import adal
import requests

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    format='jira plugin %(levelname)s - %(message)s')


class AzureClient(object):

    MANDATORY_COLUMNS = ["dss_group_name", "aad_group_name", "dss_profile"]

    # Relevant URLs
    authority_url = "https://login.microsoftonline.com/"
    graph_url = "https://graph.microsoft.com/"
    graph_group_url = "https://graph.microsoft.com/v1.0/groups?$filter=displayName eq '{}'&$select=id"
    graph_members_url = "https://graph.microsoft.com/v1.0/groups/{}/members?$select=displayName,userPrincipalName"

    # Define a translation dict that specifies how each credential should
    # be named in the user's secrets
    credentials_labels = {
        "graph_tenant_id": "Tenant ID",
        "graph_app_id": "Application ID",
        "graph_app_secret": "App secret",
        "graph_app_cert": "App certificate",
        "graph_app_cert_thumb": "App certificate thumbprint",
        "graph_user": "User principal",
        "graph_user_pwd": "User password",
    }

    def __init__(self, project_key, config):
        self.project_key = project_key
        self.azure_ad_connection = config.get("azure_ad_connection", {})
        self.flag_simulate = config.get("flag_simulate")
        self.auth_method = self.azure_ad_connection.get("auth_method")
        # Read the group configuration data from DSS
        self.groups_dataset = config.get("groups_dataset", None)
        if not self.groups_dataset:
            raise Exception("No groups dataset has been selected.")

        groups_dataset_handle = dataiku.Dataset(self.groups_dataset, self.project_key)
        self.groups_df = groups_dataset_handle.get_dataframe()

        self.client = dataiku.api_client()
        self.run_user = self.client.get_auth_info()["authIdentifier"]
        self.possible_dss_profiles = self.get_possible_dss_profiles()
        self.session = requests.Session()

        # Initialize a dataframe that will contain log data
        self.log_df = pd.DataFrame(columns=["date", "user", "type", "message"])

        # Configure auth method
        self.required_credentials = self.get_required_credentials(
            self.azure_ad_connection.get("auth_method")
        )

        # Read credentials
        if self.azure_ad_connection.get("flag_user_credentials"):
            self.credentials = self.get_credentials("user")
        else:
            self.credentials = self.get_credentials("parameters")

        # Connect to Graph API
        self.set_session_headers()

    def get_possible_dss_profiles(self):
        self.available_dss_profiles = self.get_available_dss_profiles()
        ordered_dss_profiles = self.groups_df["dss_profile"].tolist()
        self.ranked_dss_profiles = []
        for profile in ordered_dss_profiles:
            if profile in self.available_dss_profiles and profile not in self.ranked_dss_profiles:
                self.ranked_dss_profiles.append(profile)
        return self.ranked_dss_profiles

    @staticmethod
    def get_user_id(email):
        """
        Creates a user ID based on an email address.

        :param email: the email address
        """
        return email.replace("@", "_").replace("#", "_").replace("-", "_")

    @staticmethod
    def list_diff(list1, list2):
        """Return elements of list1 that are not present in list2."""
        return list(set(list1) - set(list2))

    def get_dss_profile(self, dss_profile_list):
        """
        Given an list of dss_profile types, return the most potent dss_profile.

        :param dss_profile_list: a list with dss_profiles
        """
        # For each dss_profile type, going from most to least potent, see if it is present in the list.
        # If so, return it as the assigned dss_profile type.
        for dss_profile_type in self.possible_dss_profiles:
            if dss_profile_type in dss_profile_list:
                return dss_profile_type
        # If no match was found above, default to no dss_profile
        return "NONE"

    def get_available_dss_profiles(self):
        licensing = self.client.get_licensing_status()
        user_profiles = licensing.get('base', []).get('userProfiles', [])
        user_profiles.append("NONE")
        return user_profiles

    @staticmethod
    def get_required_credentials(auth_method):
        """Determine which credentials are required, based on the authentication method.

        :param auth_method: the selected authentication method
        """
        required_credentials = ["graph_tenant_id", "graph_app_id"]

        if auth_method == "auth_app_token":
            required_credentials.extend(["graph_app_secret"])
        elif auth_method == "auth_app_cert":
            required_credentials.extend(["graph_app_cert", "graph_app_cert_thumb"])
        elif auth_method == "auth_user_pwd":
            required_credentials.extend(["graph_user", "graph_user_pwd"])
        return required_credentials

    def validate_groups_df(self):
        """Verifies that the groups data contains the correct columns and dss_profile types."""

        # Validate existence of correct columns
        column_names = list(self.groups_df.columns)
        self.assert_mandatory_columns(column_names)

        # Validate content of dss_profile column
        dss_profile_values = list(self.groups_df["dss_profile"].unique())
        impossible_dss_profiles = self.list_diff(dss_profile_values, self.possible_dss_profiles)
        if impossible_dss_profiles:
            raise Exception("Invalid dss_profile types were found in the groups configuration: {}. Valid dss_profile values are: {}".format(
                    impossible_dss_profiles,
                    self.possible_dss_profiles
                )
            )

    def assert_mandatory_columns(self, column_names):
        for mandatory_column in self.MANDATORY_COLUMNS:
            if mandatory_column not in column_names:
                raise Exception("The groups dataset is not correctly configured. {} is missing".format(mandatory_column))

    def get_credentials(self, source):
        """
        Returns a dictionary containing credentials for ADAL call to MS Graph.

        :param source: where the credentials are taken from, either 'user' or 'parameters'
        """
        # Empty list for missing credentials
        missing_credentials = []
        # Dictionary for present credentials
        credentials = {}

        if source == "user":
            # Load secrets from user profile [{key: value} ...]
            user_secrets = self.client.get_auth_info(with_secrets=True)["secrets"]
            secrets_dict = {secret["key"]: secret["value"] for secret in user_secrets}
        else:
            secrets_dict = self.azure_ad_connection
        # get token = secrets_dict.get("azure_ad_credentials")
        # For each required credential, check whether it is present
        for key in self.required_credentials:
            label = self.credentials_labels[key]
            try:
                if source == "user":
                    credentials[key] = secrets_dict[label]
                else:  # source == "parameters":
                    credentials[key] = secrets_dict[key]
                if not credentials[key]:
                    raise KeyError
            except (KeyError, IndexError):
                missing_credentials.append(label)
        if missing_credentials:
            raise KeyError("Please specify these credentials: {}".format(missing_credentials))
        return credentials

    def add_log(self, message, log_type="INFO"):
        """
        Add a record to the logging dataframe.

        :param message: The text to be logged
        :param log_type: The message type, 'INFO' by default.
        """
        new_log = {
            "date": str(datetime.datetime.now()),
            "user": self.run_user,
            "type": log_type,
            "message": message,
        }

        self.log_df = self.log_df.append(new_log, ignore_index=True)

    def clear_log(self):
        """
        Empties the log. Useful for testing.
        """
        self.log_df = pd.DataFrame(columns=["date", "user", "type", "message"])

    def save_log(self, dss_log_dataset_name):
        """
        Saves the log data to a DSS dataset.

        :param dss_log_dataset_name: The name of a DSS dataset
        """
        log_dataset = dataiku.Dataset(dss_log_dataset_name, self.project_key)
        if log_dataset.read_schema(raise_if_empty=False):
            # dataset is not empty, append new records
            log_df = log_dataset.get_dataframe()
            log_df = log_df.append(self.log_df, ignore_index=True, sort=False)
            log_dataset.write_with_schema(log_df)
        else:
            # dataset is empty, write with schema
            log_dataset.write_with_schema(self.log_df)

    def create_resulttable(self):
        """
        Transforms the log dataframe into a ResultTable.
        """
        result_table = ResultTable()

        for column_name in self.log_df.keys():
            result_table.add_column(column_name, str.capitalize(column_name), "STRING")
        for log_row in self.log_df.itertuples():
            result_table.add_record(list(log_row)[1:])
        return result_table

    def set_session_headers(self):
        """
        Starts an ADAL session with Microsoft Graph.
        """
        auth_context = adal.AuthenticationContext(
            self.authority_url + self.credentials["graph_tenant_id"], api_version=None
        )

        if self.auth_method == "auth_app_token":
            token_response = auth_context.acquire_token_with_client_credentials(
                self.graph_url,
                self.credentials["graph_app_id"],
                self.credentials["graph_app_secret"],
            )
        elif self.auth_method == "auth_app_cert":
            token_response = auth_context.acquire_token_with_client_certificate(
                self.graph_url,
                self.credentials["graph_app_id"],
                self.credentials["graph_app_cert"],
                self.credentials["graph_app_cert_thumb"],
            )
        elif self.auth_method == "auth_user_pwd":
            token_response = auth_context.acquire_token_with_username_password(
                self.graph_url,
                self.credentials["graph_user"],
                self.credentials["graph_user_pwd"],
                self.credentials["graph_app_id"],
            )
        else:
            raise Exception("Invalid authentication method")
        self.session.headers.update(
            {"Authorization": 'Bearer {}'.format(token_response["accessToken"])}
        )

    def query_group(self, group_name_aad):
        """
        AAD groups have a unique ID in Graph, which this function retrieves.

        :param group_name_aad: AAD group name
        :return: the Graph ID for the AAD group
        """
        try:
            query_url = self.graph_group_url.format(group_name_aad)
            query_result = self.session.get(query_url)
            query_result = query_result.json()
            if "value" in query_result:
                query_result = query_result["value"]
                if query_result:
                    return query_result[0]["id"]
                else:
                    self.add_log(
                        "Group {} has not been found in AAD".format(group_name_aad), "WARNING",
                    )
            elif "error" in query_result:
                raise Exception(query_result["error"].get("message"))
        except Exception as e:
            self.add_log(
                'Error calling Graph API for group "{}: {}'.format(group_name_aad, str(e)),
                "WARNING",
            )

    def query_members(self, group_id, group_name_dss):
        """
        Send query to Graph for members of a group, by ID.

        :param group_id: the ID of a group in Graph
        :param group_name_dss: DSS group name, returned in result
        :return: a dataframe with 4 columns: display name, email, groups, login
        """
        group_members = pd.DataFrame()

        try:
            query_url = self.graph_members_url.format(group_id)

            while query_url:
                query_result = self.session.get(query_url)
                query_result = query_result.json()
                query_url = query_result.get("@odata.nextLink", "")
                group_members = group_members.append(
                    pd.DataFrame(query_result["value"]), ignore_index=True
                )
            if not group_members.empty:
                # The first column is    meaningless and is removed using iloc
                group_members = group_members.drop(group_members.columns[0], axis=1)

                # Rename the columns
                group_members.columns = ["displayName", "email"]

                # Add two columns
                group_members["groups"] = group_name_dss
                group_members["login"] = group_members["email"].apply(self.get_user_id)
            else:
                self.add_log("Group '{}' has no members in AAD".format(group_name_dss))

            return group_members
        except Exception as e:
            self.add_log(
                'Group "{}" members cannot be retrieved from AAD: {}'.format(group_name_dss, str(e)),
                "WARNING",
            )

    def user_create(self, user_id, display_name, email, groups, user_dss_profile):
        """
        Create a new DSS user.

        The parameters are taken from the parameters of dataiku.client.create_user.
        """
        if user_dss_profile == "NONE":
            self.add_log(
                'User "{}" will not be created, since he has no dss_profile.'.format(user_id)
            )
            return
        if self.flag_simulate:
            self.add_log(
                'User "{}" will be created and assigned groups "{}" with the "{}" profile'.format(user_id, groups, user_dss_profile)
            )
            return
        # Create the user in DSS
        user = self.client.create_user(
            login=user_id,
            display_name=display_name,
            groups=list(groups),
            password="",
            source_type="LOCAL_NO_AUTH",
            profile=user_dss_profile,
        )

        # Request and alter the user definition to set the e-mail address
        user_def = user.get_definition()
        user_def["email"] = email
        user.set_definition(user_def)

        self.add_log(
            'User "{}" has been created and assigned groups "{}" with the "{}" profile'.format(user_id, groups, user_dss_profile)
        )

    def user_update(self, user_row, groups, message):
        """
        Update the group membership of a DSS user.

        :param user_row: the user row
        :param message: textual description of the changes
        """
        user_id = user_row["login"]
        if self.flag_simulate:
            self.add_log('User "{}" will be modified: {}'.format(user_id, message))
            return

        # Request and alter the user's definition
        user = self.client.get_user(user_id)
        user_def = user.get_definition()
        user_def["groups"] = groups
        user_def["userProfile"] = user_row["userProfile"]
        user_def["displayName"] = user_row["displayName_aad"]
        user_def["email"] = user_row["email_aad"]

        user.set_definition(user_def)

        self.add_log('User "{}" has been modified: {}'.format(user_id, message))

    def user_delete(self, user_id, reason):
        """
        Remove an user from DSS
        :param user_id: The user's login
        :param reason: reason for deletion, e.g. "No dss_profile" or "Not found in AAD"
        """
        if self.flag_simulate:
            self.add_log('User "{}" will be deleted. Reason: {}'.format(user_id, reason))
            return
        user = self.client.get_user(user_id)
        user.delete()

        self.add_log('User "{}" has been deleted. Reason: {}'.format(user_id, reason))

    def create_missing_groups(self, missing_groups):
        if self.flag_simulate:
            self.add_log(
                'Groups "{}" will be created.'.format(missing_groups)
            )
            return
        for missing_group in missing_groups:
            self.client.create_group(name=missing_group, description="Added by Azure AD Sync", source_type='LOCAL')
            self.add_log(
                'Group "{}" has been created.'.format(missing_group)
            )

    def validate_groups(self):
        # Read the group configuration data from DSS
        self.validate_groups_df()

        dss_groups = [group["name"] for group in self.client.list_groups()]

        # Compare DSS groups with the groups in the input
        groups_from_input = list(self.groups_df["dss_group_name"])
        local_groups = self.list_diff(dss_groups, groups_from_input)
        missing_groups = self.list_diff(groups_from_input, dss_groups)

        if missing_groups:
            self.create_missing_groups(missing_groups)
            local_groups.extend(missing_groups)
        return local_groups

    def get_group_members(self):
        # Init empty data frame
        group_members_df = pd.DataFrame()

        # Loop over each group and query the API
        for row in self.groups_df.itertuples():
            group_id = self.query_group(row.aad_group_name)
            if not group_id:
                continue
            group_members = self.query_members(group_id, row.dss_group_name)
            group_members_df = group_members_df.append(
                group_members, ignore_index=True
            )
        return group_members_df

    def assert_group_not_empty(self, group_members):
        if group_members.empty:
            raise Exception("There are no group members to synchronize")

    def get_aad_users(self, group_members_df):
        #  dss_profile_lookup = self.groups_df.iloc[:, [0, 2]] double check that change
        dss_profile_lookup = self.groups_df

        # Sort and group the data frame
        aad_users = (
            group_members_df.sort_values(by=["login", "groups"])
            .merge(dss_profile_lookup, left_on="groups", right_on="dss_group_name")
            .groupby(by=["login", "displayName", "email"])["groups", "dss_profile"]
            .agg(["unique"])
            .reset_index()
        )

        aad_users.columns = aad_users.columns.droplevel(1)
        return aad_users

    def get_dss_users(self):
        # Read data about groups and users from DSS
        list_users = self.client.list_users()
        dss_users = pd.DataFrame(
            list_users,
            columns=[
                "login",
                "displayName",
                "email",
                "groups",
                "sourceType",
                "userProfile",
            ],
        )
        dss_users["email"] = dss_users["email"].astype(object)  # In case of fresh new DSS with one email free admin account
        return dss_users

    def compare_users(self, aad_users, dss_users):
        # Create a comparison table between AAD and DSS
        user_comparison = aad_users.merge(
            dss_users,
            how="outer",
            on=["login"],
            suffixes=("_aad", "_dss"),
            indicator=True,
        )
        # Replace NaN with empty lists in the dss_profile column
        for row in user_comparison.loc[
            user_comparison.dss_profile.isnull(), "dss_profile"
        ].index:
            user_comparison.at[row, "dss_profile"] = []
        return user_comparison

    def sync_user(self, user, local_groups):
        user_id = user["login"]
        user_dss_profile = self.get_dss_profile(user["dss_profile"])

        # If user only exists in AAD, create the user.
        # The user_create function checks whether the user has a dss_profile.
        if self.is_only_in_aad(user):
            self.user_create(
                user_id=user_id,
                display_name=user["displayName_aad"],
                email=user["email_aad"],
                groups=user["groups_aad"],
                user_dss_profile=user_dss_profile,
            )
            return

        if self.is_only_in_dss(user):
            # The user exists only in DSS as a LOCAL_NO_AUTH account: delete.
            if self.is_no_auth_user(user):
                self.user_delete(user_id, "Not found in AAD.")
            return

        # The user exists in AAD, and in DSS as LOCAL or LDAP type.
        # This is strange, and it is logged as a warning.
        if not self.is_no_auth_user(user):
            self.add_log(
                "User {} has DSS user type {}, while LOCAL_NO_AUTH was expected".format(user_id, user["sourceType"]),
                "WARNING",
            )
            return

        # The user exists in DSS, but its AAD memberships don't grant a dss_profile: delete.
        if user_dss_profile == "NONE":
            self.user_delete(user_id, "No dss_profile.")
            return

        # Compare group memberships in DSS & AAD. If any discrepancies are found: update.
        self.update_group_memberships(user, local_groups)

    @staticmethod
    def is_only_in_aad(user):
        # The _merge column was created by the indicator parameter of pd.merge.
        # It holds data about which sources contain this row.
        return user["_merge"] == "left_only"

    @staticmethod
    def is_only_in_dss(user):
        # The _merge column was created by the indicator parameter of pd.merge.
        # It holds data about which sources contain this row.
        return user["_merge"] == "right_only"

    @staticmethod
    def is_no_auth_user(user):
        return user["sourceType"] == "LOCAL_NO_AUTH"

    def update_group_memberships(self, user, local_groups):
        user_dss_profile = self.get_dss_profile(user["dss_profile"])
        # Compare group memberships in DSS & AAD. If any discrepancies are found: update.
        users_local_groups = list(set(user["groups_dss"]) & set(local_groups))
        users_aad_groups = list(set(user["groups_dss"]) - set(local_groups))
        all_groups = list(user["groups_aad"])
        all_groups.extend(users_local_groups)

        log_message = ""
        # check for new AD groups
        if self.list_diff(all_groups, user["groups_dss"]):
            log_message += " groups {}".format(all_groups)
        # check for revoked membership AD groups
        if self.list_diff(users_aad_groups, all_groups):
            log_message += " groups {}".format(all_groups)

        if user_dss_profile != user["userProfile"]:
            user["userProfile"] = user_dss_profile
            log_message += " profile {}".format(user_dss_profile)
        if user["displayName_aad"] != user["displayName_dss"]:
            log_message += " display name {}".format(user["displayName_aad"])
        if user["email_aad"] != user["email_dss"]:
            log_message += " email {}".format(user["email_aad"])

        if log_message:
            self.user_update(user_row=user, groups=all_groups, message=log_message)
