# Camel: Basic CAM features for OnShape

## Introduction

Camel is a suite of CAM (Computer Aided Manufacturing) features for [OnShape](https://www.onshape.com/)
implemented in FeatureScript. It's an experimental hobby project that provides basic features for
generating tool paths for driving CNC machines from within a Part Studio.

If you don't already have the Camel features installed, [get them here](https://cad.onshape.com/documents/5892b0a436ab36124fe4db4b/w/782c826b12b074a8c7249ebb/e/390698553293f7f54851d374).

## Web application

This repository contains the Camel web application to help you download G-Code files generated by
Camel from a right-side element panel in your OnShape Part Studios. After you've downloaded the
G-Code files, you can preview the results with a G-Code simulator such as [Camotics](https://camotics.org/)
or load them into your CNC software to begin manufacturing right away!

To use the Camel web application, you must [subscribe to it in the OnShape App Store](https://appstore.onshape.com/apps/CAM/I4R3GCXD4XN6MBLZ3LHPI5VGCVARDSCVUGE5QHY=/description). It's free and open source.

After you've subscribed to the application, you will find the new Camel panel in the right side of
your OnShape Part Studios.

## Permissions

Here's an explanation of the permissions requested by the application:

* **Read your profile information**: Only used to get your name during authentication.
* **Read from your documents**: Only used to read variables that contain G-Code files generated by Camel from your Part Studios.

## How it works

Camel's post processor stores each G-Code files that it generates into a separate variable in your
Part Studio named `camelFile###`. It also stores an index of these files in a variable named
`camelFileIndex`.

You can see these variables in the OnShape variable view. Unfortunately, OnShape truncates long
variables in that view so we need a different way to download their contents.

Each time you open the Camel panel, OnShape sends a request to this application to render the
content to show in the panel. If necessary at the start of a session, this application then
sends a request back to OnShape to request authorization to use the OnShape API on your
behalf. You may be prompted to grant permissions at that time.

Once this application has received authorization, it calls Feature Script functions
within your Part Studio to retrieve the file index and it presents a list of file download
links to you.

Only you can access your own files. Your authorization tokens are only stored in memory for the
duration of your session, they are never stored anywhere else, and they are never shared
with anyone else.

## Alternatives

If you choose not to use this web application, you can instead choose to copy-paste G-Code directly
from the OnShape Notices panel. Simply check the **Write output to notices** checkbox in the **CAM Post process**
feature.

Or you could use curl or a similar program to download your files from the command-line
using the OnShape API [directly](https://cad.onshape.com/glassworks/explorer/#/PartStudio/evalFeatureScript)
in your own way.

## How to set up your own instance

If you don't want to use the official instance of Camel or if you'd like to make contributions,
you can run your own instance. Here's how to do it.

You'll need to be familiar with Docker and with how to set up a web server.

* Visit the [OnShape Developer Portal](https://dev-portal.onshape.com/) and register your application. You'll need to provide some information to identify your application. When finished, you will receive an OAuth2 client id and secret, save them for later and keep them private!
  * **Name**: A unique name for your instance. The official instance is called `Camel`.
  * **Primary format**: A unique identifier for your instance. The official instance is identified as `camel.brownstudios.dev`.
  * **Redirect URLs**: `https://example.com/oauth/redirect` (edit for your host name).
  * **OAuth URL**: `https://example.com/oauth/signin` (edit for your host name).
  * **Permissions**: Only needs **read your profile information** and **read your documents**.
* Once your application has been registered, use the OnShape Developer Portal to add the necessary extensions.
  * Panel
    * **Name**: `CAM panel`
    * **Context**: `Element right panel`
    * **Action URL**: `https://example.com/action/d/{$documentId}/{$workspaceOrVersion}/{$workspaceOrVersionId}/e/{$elementId}/panel` (edit for your host name).
    * **Icon**: The Camel icon was sourced from [here](https://www.svgrepo.com/svg/317181/camel) until someone draws something better.
* Download the code from the repository.
* Copy `.env.example` to `data/.env`.
* Edit `data/.env` as follows.
  * **`SESSION_ID_COOKIE_SECRET`**: Set this to a randomly generated string and keep it secret.
  * **`ONSHAPE_APP_CLIENT_ID`**: Set this to the OAuth2 client identifier you received from the OnShape Developer Portal.
  * *`ONSHAPE_APP_CLIENT_SECRET`**: Set this to the OAuth2 client secret you received from the OnShape Developer Portal and keep it secret.
  * **`EXTERNAL_HOSTNAME`**: Set this to the host name of the web server you will run the application on. The official instance is at `camel.brownstudios.dev`.
* Obtain an SSL certificate for your host name using a method of your choice and copy your certificate to `data/certs/cert.pem` and your private key to `data/certs/privkey.pem`. If you have [certbot](https://certbot.eff.org/) installed, you can run the `update-certs.sh` shell script to automatically obtain an SSL certificate from [Let's Encrypt](https://letsencrypt.org/) and store it in the correct location.
* Build the Docker image: `docker-compose build`.
* Run the Docker image: `docker-compose up`.

Then just visit your app's page in the [OnShape App Store](https://appstore.onshape.com/), subscribe to your
app, grant authorization, and have fun!
