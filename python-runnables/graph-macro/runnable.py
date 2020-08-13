"""
The macro checks which DSS groups are available in Azure Active Directory
The users of those AAD groups are then synchronised with DSS users of type "LOCAL_NO_AUTH"
"""
from dataiku.runnables import Runnable
from azure_client import AzureClient


class MyRunnable(Runnable):
    """The base interface for a Python runnable"""

    def __init__(self, project_key, config, plugin_config):
        """
        Initialize the macro.

        :param project_key: the project in which the runnable executes
        :param config: the dict of the configuration of the object
        :param plugin_config: contains the plugin settings
        """

        # Assign input to self
        self.client = AzureClient(project_key, config)
        self.log_dataset = config.get("log_dataset")

    def get_progress_target(self):
        """
        This defines the progress target, the highest value that progress_callback can return.
        Since the macro contains four steps, the target is four.
        """
        return 4, "NONE"

    def run(self, progress_callback):
        """
        The main method of Macro runnable.

        :param progress_callback: standard parameter for DSS runnable
        """

        try:
            progress_callback(0)
            local_groups = self.client.validate_groups()

            progress_callback(1)
            group_members = self.client.get_group_members()

            progress_callback(2)
            self.client.assert_group_not_empty(group_members)
            aad_users = self.client.get_aad_users(group_members)

            progress_callback(3)
            dss_users = self.client.get_dss_users()
            user_comparison = self.client.compare_users(aad_users, dss_users)
            for _, user in user_comparison.iterrows():
                self.client.sync_user(user, local_groups)

            progress_callback(4)  # Phase 4 completed - macro has finished

        except Exception as e:
            self.client.add_log(str(e), "ERROR")
        finally:
            if self.log_dataset:
                self.client.save_log(self.log_dataset)
            return self.client.create_resulttable()
