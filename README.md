# Camel: Basic CAM features for OnShape

## Introduction

Camel is a suite of CAM (Computer Aided Manufacturing) features for [OnShape](https://www.onshape.com/)
implemented in FeatureScript. It's an experimental hobby project that provides basic features for
generating tool paths for driving CNC machines from within a Part Studio.

If you don't already have the Camel features installed, [get them here](https://cad.onshape.com/documents/5892b0a436ab36124fe4db4b/w/782c826b12b074a8c7249ebb/e/2ed99a22b7f3f226e33a8245).

## Web application

This repository contains the Camel web application to help you download G-Code files generated by
Camel from a right-side element panel in your OnShape Part Studios. Once you've downloaded the
G-Code files, you can preview the results with a G-Code simulator such as [Camotics](https://camotics.org/)
or load them into your CNC software to begin manufacturing right away!

To use the Camel web application, you must [subscribe to it in the OnShape App Store](https://appstore.onshape.com/apps/CAM/I4R3GCXD4XN6MBLZ3LHPI5VGCVARDSCVUGE5QHY=/description). It's free and open source.

Once you've subscribed to the application, you will find the new Camel panel in the right side of
your OnShape Part Studios.

## Permissions

Here's an explanation of the permissions requested by the application:

* **Read from your documents**: Only used to read variables that contain files generated by Camel features in your Part Studios.

## How it works

Camel's post processor stores each file that it generates into a separate variable in your
Part Studio named `camelFile###`. It also stores an index of these files in a variable named
`camelFileIndex`.

You can see these variables in the OnShape variable view. Unfortunately, OnShape truncates long
variables in that view so we need a different way to download their contents.

Each time you open the Camel panel, OnShape sends a request to this application to render the
content to show in the panel. If necessary at the start of a session, this application
sends a request back to OnShape to request authorization to use the OnShape API on your
behalf. You will be prompted to grant permissions to this application at that time if you
haven't already done so.

Once this application has received authorization, it calls Feature Script functions
within your Part Studio to retrieve the file index and it presents a list of links to
download or view the files.

Only you can access your own files. Your authorization tokens are only stored in the server's
memory for the duration of your session; they are never stored anywhere else and they are
never shared with anyone else.

## Alternatives

If you choose not to use this web application, you can instead choose to copy-paste files directly
from the OnShape Notices area. Simply enable the **Write output to notices** checkbox in the
**CAM Post process** feature, save your changes, then open the Notices area to find your files.

Or you could use 'curl' or a similar program to download your files from the command-line
using the [OnShape API](https://cad.onshape.com/glassworks/explorer/#/PartStudio/evalFeatureScript)
in your own way.

## How to set up your own instance

If you don't want to use the production instance of Camel or if you'd like to make contributions,
you can run your own instance. Here's how to do it.

You'll need to be familiar with Docker and with how to set up a web server.

* Visit the [OnShape Developer Portal](https://dev-portal.onshape.com/) and click **Create new OAuth application**. You'll need to provide some information to identify your application. When finished, you will receive an OAuth2 client id and secret, save them for later and keep them private!
  * **Name**: A unique name for your instance. The production instance is called `Camel`.
  * **production format**: A unique identifier for your instance. The production instance is identified as `camel.brownstudios.dev`.
  * **Redirect URLs**: `https://example.com/oauth/redirect` (edit for your host name).
  * **OAuth URL**: `https://example.com/oauth/signin` (edit for your host name).
  * **Permissions**: Only needs **read your documents**.
* In the **Extensions** tab of the portal, click **Add extension** to add the necessary extensions.
  * Panel
    * **Name**: `CAM panel`
    * **Location**: `Element right panel`
    * **Context**: `Inside part studio`
    * **Action URL**: `https://example.com/action/d/{$documentId}/{$workspaceOrVersion}/{$workspaceOrVersionId}/e/{$elementId}/panel?configuration={$configuration}` (edit for your host name).
    * **Icon**: Upload `icons/camel.svg`.
* In the **Details** tab of the portal, click **Create store entry** to publish the application to the OnShape App Store.  Fill in the form as required.
* Download the application's source code.
* Copy `.env.example` to `.env`.
* Edit `.env` as follows.
  * **`SESSION_ID_COOKIE_SECRET`**: Set this variable to a randomly generated string and keep it secret.
  * **`ONSHAPE_APP_CLIENT_ID`**: Set this variable to the OAuth2 client identifier you received from the OnShape Developer Portal. Make sure to copy the string precisely, including any trailing `=` signs.
  * **`ONSHAPE_APP_CLIENT_SECRET`**: Set this variable to the OAuth2 client secret you received from the OnShape Developer Portal and keep it secret. Make sure to copy the string precisely, including any trailing `=` signs.
  * **`EXTERNAL_HOSTNAME`**: Set this variable to the host name of the web server you will run the application on. The production instance is at `camel.brownstudios.dev`.
* Obtain an SSL certificate for your host name using a method of your choice and copy your certificate to `data/certs/cert.pem` and your private key to `data/certs/privkey.pem`. If you have [certbot](https://certbot.eff.org/) installed, you can run the `update-certs.sh` shell script to automatically obtain an SSL certificate from [Let's Encrypt](https://letsencrypt.org/) and store it in the correct location.
* Build the Docker image: `docker-compose build`.
* Run the Docker image: `docker-compose up`.
* A few months later when it's time to renew your SSL certificates, run the `restart-with-updated-certs.sh` script to stop the service, update your certificates from Let's Encrypt, and start the service again.

Then visit your app's page in the [OnShape App Store](https://appstore.onshape.com/), subscribe to your
shiny new app, grant it permissions, and have fun!
