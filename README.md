![dsabot](https://user-images.githubusercontent.com/115161133/233079779-f2ffa7ca-248e-45b1-87b6-8876aed0a7a1.jpg)

# DSAbot infosec tool
DSAbot is the acronymous of Dependency Security Analyzer bot. 
Its purpose is to orchestrate the integration of *Dependency Track with GitHub and Defect Dojo*.
Also, DSAbot generates a third-party components inventory in CyloneDX standard format and ingest it for security vulnerability scanning.
It is written in Node.js

## What does DSAbot do? 

1. Receive GitHub Merged PR event
2. Analyze - Parse - Validate JSON payload data
3. Execute trivy binary to generate SBOM file from repository
4. Ingest the SBOM json file in Dependency Track
5. Check if Product and Engagement exists in Defect Dojo
6. Create Product or Engagement if necessary
7. Update Engagement in Dependency Track if necessary

All the transactions should be logged and validated.
All of the integration process should be encrypted.

This is a Node.js web application that interacts with the GitHub API and AWS S3 to generate and upload SBOM (Software Bill of Materials) files. It also uses a dependency tracking tool called Dependency-Track to ingest the SBOM files and generate reports on the project's dependencies.

The application listens to incoming webhook events from GitHub and uses the data to generate SBOM files for the relevant repository. It can also retrieve a list of all the repositories in an organization and generate SBOM files for each repository.

The Dependency-Track tool is used to ingest the files and generate dependency reports. The application has some built-in error handling and logging, and it relies on environment variables for configuration.

## Cloning the repository

``` 
git clone https://github.com/security-opensource/dsabot.git
```
## Documentation for API Endpoints

All URIs are relative to *https://dsabot-api-main.staging.company_domain.com*

HTTP request | Description
------------ | -------------
**GET** / | get help
**GET** /status | get Status
**GET** /sbom | Build specific SBOM file from parameters (repo & branch) to ingest into Dependency Track
**GET** /:org:/repos | get All repositories
**GET** /:org:/:repo/:branch/webhook | Build specific SBOM file from org;repo;branch to ingest into Dependency Track
**POST** /webhook | Receive GitHub Webhook to ingest SBOM into Dependency Track


## Setup
 ```mermaid
graph TD;
    GitHub-WebHook-->DSAbot-API;
    DSAbot-API-->GitHub-Repository;
    GitHub-Repository-->DSAbot-API;
    DSAbot-API-->Dependency-Track;
```
