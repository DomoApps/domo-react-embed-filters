<div align="center">
  <img src="https://github.com/domoinc/domo-node-sdk/blob/master/domo.png?raw=true" width="400" height="400"/>
</div>

# React - Private Embed with Programmatic Filtering + Edit Experience Example Code

_****Please note that this code is for demonstration purposes only and should not be used in a production environment._ 

### Setup

1. Install Node.js https://nodejs.org/en/download/
2. In the base folder of the repository run npm install to install the necessary dependencies.
3. Using your favorite text/code editor (Recommend using Visual Studio Code or something similar) modify the existing file in the base folder of the project named .env (this file is a hidden file, so if you can't find it, you'll need to show hidden files in your file explorer).
4. Inside of this file change the following configuration settings but using your own values (Not all values are required, just for the section (Edit/Programmatic) you're testing):
   ```
   #This is for Programmatic Filtering 
   DOMO_CLIENT_ID=
   DOMO_CLIENT_SECRET=
   
    #This is for Edit Embed
    JWT_SECRET=
    KEY_ATTRIBUTE=
    IDP_URL=
   ```

### Programmatic Filtering

* The CLIENT_ID and CLIENT_SECRET is used to create the access token which will be used to then create an embed token for use with the private embed. For more information about creating the CLIENT_ID and CLIENT_SECRET see **https://developer.domo.com/docs/authentication/overview-4**.

* The client Id + Secret need the following scopes: data, audit, user, dashboard

### Edit Embed

* The IDP_URL is the Embed URL for Identity Broker is the URL that receives authentication, verifies the user, and
  routes to the correct place. It is found in your primary Domo instance under Admin -> Domo Everywhere -> Embed ->
  Routing
* The JWT_SECRET is the authentication method for authenticating to the IDP. This value should be kept safe. It is found
  in your primary Domo instance under Admin -> Domo Everywhere -> Embed -> Routing -> Change Authentication Method to
  JWT Secret, then click "Generate Secret"
* The KEY_ATTRIBUTE is the variable name that you pass to denote which user gets routed to which instance. The name is
  customizable, so this variable name must match the value that is defined in Domo. Verify by looking in Admin -> Domo
  Everywhere -> Embed -> Mapping and seeing the value in the "Key Attribute" section. The defined value in this variable
  must match what is listed in Domo.

5. Start the express server like this in the base folder of the project (you will run this command in either Terminal/Shell(Mac/Linux) or Command Prompt/Powershell(Windows)
   ```
   # For Mac
      ./start-dev.sh
   # For Windows
      start start-dev.bat
   ```
6. In your browser go to the url localhost:3000 or the url that is listed in the terminal after you start the server.
   Log in with the default user account
   ```
   Username: admin
   Password: admin 
    ```
7. Locate or create the dashboard or card that you would like to embed in Domo.
8. Embed the card or dashboard using the 'Private' Embed option and retrieve the Embed ID of the dashboard
9. Once you log in, click the "Manage User" button in the bottom left and edit the default user or create your own user.
   In this menu, you will be able to add your embed IDs and filters to determine what content will render. If you want
   to use Edit Embed, you can set the embed ID to "edit" and it will follow the JWT authentication method for edit
   embed. 

### Notes & Caveats

* If you ahve whitelisting set up in your Domo instance, you will need to whitelist the domain that you are using to
  run this application.  They can be found at the following locations: https://{your_instance}.domo.com/admin/security/privateEmbedDomains & https://{your_instance}.domo.com/admin/domo-everywhere/settings
* If you want to change the Logo that is displayed on the login screen, you can modify the URL for the logo in the .env file.  
* If you want to change the favicon, you can replace the favicon.ico in the public folder.