# Azure Active Directory Sync Plugin

This Dataiku plugin provides a macro to synchronize the list of Dataiku users with those present on your [Azure AD](https://azure.microsoft.com/services/active-directory/).

> [!WARNING]
> Starting with Dataiku version 14 this plugin is considered \"deprecated\", we recommend using the native [Azure AD user synchronization](https://doc.dataiku.com/dss/latest/security/authentication/azure-ad.html).

This Dataiku plugin completes your SSO setting by offering some degree of synchronization between selected groups of Azure Active Directory users and the Dataiku user list.

## How to set up

1.  From the [Azure Portal](https://portal.azure.com/), go to **Azure Active Directory \> App registrations** create a new App (**New registration**).
2.  Click on the newly created app. Copy the Application ID. Then go to the **Certificates & secrets \> New client secret** tab. Set a description, choose an expire date, and copy the value of the created secret.
3.  Then navigate to the **API permissions \> Microsoft Graphs \> Application permissions** and add the following permissions: **Group.Read.All** and **User.Read.All**. Finally, grant admin consent for these permissions.
4.  Find you tenant ID by navigating to [Azure Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties) \> Azure AD \> Manage \> Properties
5.  Once the plugin is installed, go to **App \> Plugins \> Installed \> Azure Active Directory Sync \> Settings**.
6.  Create an authentication preset using the Application ID, Secret ID and tenant ID.

## How to use

1.  In a Dataiku project, create a table containing the following columns:
    - Dataiku_group_name
    - aad_group_name,
    - Dataiku_profile
2.  For each row, give the name of the group on AAD, its equivalent group name on Dataiku, and the user profile you which to associate to this group. The profile can take the following values: DATA_SCIENTIST, DATA_ANALYST, EXPLORER or READER.
3.  A second dataset can be created for logging purpose. This dataset should contain the following columns:
    - date
    - user
    - type
    - message
4.  In the Dataiku project containing the group dataset, go to the macro menu and select **Synchronize Azure AD Users with Dataiku**. Select the Azure AD connection created in step 2 of the set up phase,  and point Group dataset and Save logging into toward the correct datasets.
5.  First make sure **Simulate** is selected, and press **Run Macro**. A list of the operation to be performed should appear.
6.  Once you are happy with the synchronization operation to be performed, unselect **Simulate** and run the macro.

## Limitations

Please note that:

- Users created on the Dataiku side will have Dataiku handles based on their Azure Active Directory email address, with @ and \# being replaced by an underscore character. 
- Local users already created on Dataiku will be untouched by the synchronization.
- Any change on users performed on the Dataiku side will not be reflected on Azure AD. The AD remains the source of truth for synchronized users.


## Licence
This plugin is distributed under the Apache License version 2.0
