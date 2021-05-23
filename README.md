# Sample Python B2C Application
This solution consists of a simple Python solution that can be used to experiment with [Azure AD B2C](https://docs.microsoft.com/en-us/azure/active-directory-b2c/).  The solution is built using the [Flask web framework](https://flask.palletsprojects.com/en/1.1.x/). The [Microsoft Authentication Library (MSAL)](https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-overview) to obtain Open ID Connect ID tokens and OAuth access tokens.

The solution can be deployed to run directly on a machine or be can run as a set of containers.

## What problem does this solve?
Azure AD B2C provides a powerful solution to the business-to-consumer (B2C) identity problem.  The Python samples for Azure AD B2C demonstrate basic authentication, but do not demonstrate the more powerful features of the service such as step-up authentication and how Azure AD B2C can be used to secure access to an API.  This solution seeks to demonstrate those capabilities.

This solution is built to a business case where an insurance company needs wants to provide their customers with the ability to view and administer their insurance policies. The customer accesses the information via a web front end which makes calls to an API which in turns queries the database containing the policy information.

## The design
The solution consists of a web front-end, API backend, and simple JSON file acting as the database for insurance policy information. Access to the web front-end application is secured using Azure AD B2C. The front-end application communicates with the API backend which is secured with Azure B2C. The API backend processes calls to the policy information records for the user stored in the JSON file.

![solution design](https://github.com/mattfeltonma/python-b2c-sample/blob/master/images/b2c-app.png)

The following scenarios below can be demonstrated with this solution:

* Allow the user to sign up for a new account for the application which is stored in Azure AD B2C
* Allow an existing user to reset their password
* Authenticate the user to the web front end using Open ID Connect via Azure AD B2C
* Allow the user to modify their user profile which consists of attributes collected at sign-up
* Application to application authentication and authorization using OAuth access tokens and authorization scopes
* Step-up authentication by requiring MFA authentication when a user performs a privileged operation such as modifying the beneficiary on an insurance policy
* View the claims being passed in the user's ID token
* Logout of the web front end application

## Setup

1. [Setting up the Azure B2C Directory](https://journeyofthegeek.com/2020/06/22/python-sample-web-app-and-api-for-azure-ad-b2c/#setting-up-b2c)

2. [Option 1 - Running the code directly on your machine](https://journeyofthegeek.com/2020/06/22/python-sample-web-app-and-api-for-azure-ad-b2c/#option-1-running-code-directly)

3. [Option 2 - Running the code in containers](https://journeyofthegeek.com/2020/06/22/python-sample-web-app-and-api-for-azure-ad-b2c/#option-2-running-as-containers)


