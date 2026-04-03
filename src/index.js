import express from "express";
import { exec } from "child_process";
import fs from 'fs';
import dotenv from 'dotenv';
import axios from 'axios';
import FormData from 'form-data';
import { getParametersData } from './lib/getParametersData.js';
import { getWebhookData } from './lib/getWebhookData.js';
import * as validate from './lib/validateRequests.js';
import rateLimit from 'express-rate-limit';

// Configure rate-limit to OTP
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutos
  max: 10,  // limitar cada IP a 3 solicitudes por windowMs
  message: "Too many requests created from this IP, please try again later."
});

dotenv.config({ path: './.env' });
const app = express();
const param=getParametersData();

function jsonVerify(req, res, buf) {
  try {
    JSON.parse(buf);
  } catch (err) {
    return res.status(400).send({ error: 'DEBUG:ERR:RCV: Invalid JSON format: ' + buf });
  }
}

app.use(express.json({ verify: jsonVerify }));
app.use('/img',express.static('img'));

app.get('/',(req,res) => {
  res.send(`InfoSec Tool - DSAbot`);
})

app.get('/status',(req,res) => {
   res.status(200).send('The process was completed');
})

//  Do the SCA process for the repo and branch
app.get('/sbom', otpLimiter , (req, res) => {

  res.setHeader('Content-Type', 'text/html');
  res.write('<html><body>');


  const data = {};
  data.number = '0.0.0';
  data.repositoryName = req.query.repo;
  data.base = req.query.branch;
  data.urlRepository = `${param.GH_URL_ORG}${data.repositoryName}`;  
  data.sbomLocalFileName = `temp/my_sbom_files/${param.BOM_PREFIX_FILE}${data.repositoryName}${param.STR_SEPARATOR}${data.number}${param.JSON_EXTENSION}`;

  if (data.repositoryName == "repository_name"  && data.base == "branch_name") {
    res.write(`<p></p>`);
    res.write(`<p><img src="${req.protocol}://${req.headers.host}/img/ipsy.png" alt="DSAbot"></p>
    <p><b>Enter new repository and branch</b></p>
    `);
    res.end('</body></html>');
  } else { 
    res.write(`<p>Generating...</p>`);
    createSBOM(data)
    .then(async (stdout) => {
      console.log(stdout);
      const fileContent = readSBOM(data.sbomLocalFileName);
      data.sbomFileName = `${param.BOM_PREFIX_FILE}${data.repositoryName}${param.JSON_EXTENSION}`;

      try {
        const response = await uploadSbomToDtrack(param, data, fileContent);
        console.log(response);
      // file deepcode ignore XSS: <please specify a reason of ignoring this>
      
        await getDTrackProject(param, data);
        res.write(`<p><img src="${req.protocol}://${req.headers.host}/img/ipsy.png" alt="DSAbot"></p>
        <p>The generation of the <b>${data.repositoryName}</b> repository and <b>${data.base}</b> branch was successful.</p>
        <p>Click on the following link and then go to the <b>Audit Vulnerabilities</b> tab of the project to view the detected vulnerabilities.</p>
        <p><b><a href="${param.DTRACK_PROJECTS_URL}${data.projectUUID}" target="_blank">${data.repositoryName}/${data.base}</a></b></p>
        <p>This process may take a few minutes</p>
        `);
        res.end('</body></html>');
        // Continuar con el resto del código si es necesario
      } catch (error) {
        console.error(error);
        // Manejar el error de manera apropiada
      }    
      removeSBOM(data);
    })
    .catch(err => {
      console.log(err);
      res.write(`<p><img src="${req.protocol}://${req.headers.host}/img/ipsy.png" alt="DSAbot"></p>
            <p style="color: red;">The generation of the <b>${data.repositoryName}</b> repository and <b>${data.base}</b> branch was not successful.</p>
            <p>possibleCause: The repository name or branch name are case sensitive, please check the upper and lower case.</p>
            `);
      res.end('</body></html>');  
    });
  }
});

//  Do the SCA process for the repo and branch
app.get('/:org/:repo/:branch/webhook', (req, res) => {
  //  TO DO: add rate limit, headers protection (helmet protection or similar)
  
  const payloadDataPost = {
    action: 'closed',
    number: '0.0.0',
    pull_request: {
      state: 'closed',
      base: {
        ref: req.params.branch
      },
      merged: true
    },
    repository: {
      name: req.params.repo,
      html_url: `https://github.com/${req.params.org}/${req.params.repo}`
    }
  }
  let requestOptionDSAbot = {
    method : 'post',
    url: param.DSABOT_WEBHOOK_URL,
    headers: {
      'Content-Type': 'application/json',
      'X-GitHub-Event': 'pull_request'
    },
    data: payloadDataPost
  };

  return axios.request(requestOptionDSAbot)
  .then((response) => {
    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:SUCCESS:DSABOT: DSAbot invoked successfully: ${req.params.org} - ${req.params.repo} - ${req.params.branch}`);
      const result = {
        status: response.status,
        message: `INFO:SUCCESS:DSABOT: DSAbot invoked successfully ${req.params.org} - ${req.params.repo} - ${req.params.branch}`,
        action: 'DSAbot invoked',
        organization: req.params.org,
        repository: req.params.repo,
        branch: req.params.branch,
        responseData: response.data
      };
      const jsonResult = JSON.stringify(result);
      console.log(jsonResult);
      return res.status(200).send(`INFO:SUCCESS:DSABOT: DSAbot invoked successfully ${req.params.org} - ${req.params.repo} - ${req.params.branch}`);
  })
  .catch((error) => {
    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:DSABOT: Error requesting to DSAbot successful ${req.params.org}/${req.params.repo}`);
    let result;
    if (error.response) {
      result = {
        status: error.response.status,
        message: `INFO:ERR:DSABOT: Error requesting to DSAbot ${req.params.org}/${req.params.repo} info: ${error.response.data}`,
        action: 'DSAbot invoked',
        organization: req.params.org,
        repository: req.params.repo,
        branch: req.params.branch,
      }
    } else {
      result = {
        status: 500,
        message: `INFO:ERR:DSABOT: Error requesting to DSAbot ${req.params.org}/${req.params.repo} info: ${error.message}`,
        action: 'DSAbot invoked',
        organization: req.params.org,
        repository: req.params.repo,
        branch: req.params.branch,
      }
    }
    const jsonResult = JSON.stringify(result);
    console.log(jsonResult);
    res.status(500).send("INFO:ERR:DSABOT: Error invoking DSAbot");
  });
}); 

//  Get all repositories in the organization
app.get('/:org/repos', async (req,res) => {
  try {
    let organization=req.params.org;
    const apiUrl = `https://api.github.com/orgs/${organization}/repos?per_page=100`;
    const token = process.env.GITHUB_TOKEN;
    let allRepositories = [];
  
    function parseLinkHeader(linkHeader) {
      const links = {};
      if (linkHeader) {
        linkHeader.split(',').forEach(link => {
          const parts = link.split(';');
          const url = parts[0].trim().slice(1, -1);
          const name = parts[1].trim().slice(5, -1);
          links[name] = { url };
        });
      }
      return links;
    }

    async function getRepositories (url) {
      try {
        const response = await axios.get(url, {
          headers: {
            'Authorization': `Token ${token}`,
            'User-Agent': 'MyGithubApp',
            'Accept': 'application/vnd.github+json'
          }
        });

        if (response.status >= 400) {
          console.error(response.data);
        } else {
          console.log (response.data)
          const repositories = response.data;
          repositories.forEach(repository => {
            allRepositories.push({
              "action": repository.action,
              "pull_request": {
                "state": repository.state,
                "base": {
                  "ref": repository.default_branch,
                },
              },
              "merged": repository.merged,
              "repository": {
                "name": repository.name,
                "html_url": repository.html_url,
                "archived" : repository.archived,
                "disabled" : repository.disabled,
                "visibility" : repository.visibility,
                "default_branch:" : repository.default_branch
              }
            });
          });          

          // Check if there's another page of results
          const links = parseLinkHeader(response.headers.link);
          if (links.next) {
            await getRepositories(links.next.url);
            console.log("url: "+links.next.url);
          } 
        }
      } catch (error) {
        console.error(error);
      }
    }                                      

    await getRepositories(apiUrl);
// file deepcode ignore PT: <please specify a reason of ignoring this>

    let jsonRepos=JSON.stringify(allRepositories,null,2);
    let nameOrgFile='temp/my_sbom_files/'+organization.concat(param.JSON_EXTENSION);
    fs.writeFile(nameOrgFile, jsonRepos, 'utf8', function (err) {
      if (err) {
        logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:WRCV: An error occured while writing Repositories GitHub to File. ${err}`);
      } else {
        logDebugIfEnabled(param.APP_DEBUG, `DEBUG:SUCCESS:WRCV: Repositories GitHub file has been saved: ${organization}${param.JSON_EXTENSION}`);
      }
    });
  } catch (err) {
    logDebugIfEnabled(param.APP_DEBUG, "DEBUG:ERR:WRCV:Catched: An error occured while writing Repositories GitHub to File.");
  }
  res.status(200).send('The process was completed');
});

/*  Temporarily disabled because it generates high computational processing
//  this Endpoint process all sbom files from all organization repos
app.get('/:org/sbom', async(req,res) => {
  const organization = req.params.org;
  let nameOrgFile='temp/my_sbom_files/'+organization.concat(param.JSON_EXTENSION);

  const fileContent = fs.readFileSync(nameOrgFile, function(err, data) {
    if (err) {
      logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:RREPOS: Org Repos Reading generate the following error - First Execute /:org/repos to generate Repositories List File:${err}`);
    }
  });
  logDebugIfEnabled(param.APP_DEBUG, `DEBUG:INFO:ORG_SBOM: Org: ${organization} - Org File: ${nameOrgFile}`);
  const repositories = JSON.parse(fileContent);
  let urlRequestBot;

  for (const repository of repositories) {
    if (repository.repository.name) {
      urlRequestBot = 'http://127.0.0.1:3000/' + organization + '/' + repository.repository.name + '/' + repository.pull_request.base.ref + '/sbom';
      // Send the GET request
      request.get(urlRequestBot, (err, res, body) => {
        if (err) {
          // Handle the error
          console.error(`Error: ${err}`);
          return;
        }
        logDebugIfEnabled(param.APP_DEBUG, `DEBUG:INFO:DTRACK: Status code: ${res.statusCode} - Response body: ${body} - Info: ${urlRequestBot}`);
      });
      await new Promise(resolve => setTimeout(resolve, 5000)); // add a delay between requests
    }
  }
  res.status(200).send('The process was completed');
});
*/

// Save JSON payload to local disk -> func(fileName, jsonContent)
function writePayloadToJsonFile( fileName, jsonDataStr) {
    try {
      fs.writeFile(fileName, jsonDataStr, 'utf8', function (err) {
        if (err) {
          logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:WRCV: An error occured while writing GitHub JSON Object to File. ${err}`);
        }
        logDebugIfEnabled(param.APP_DEBUG, `status: 200, message: DEBUG:SUCCESS:WRCV: GitHub JSON file has been saved. `);
      });
    } catch (err) {
      logDebugIfEnabled(param.APP_DEBUG, "DEBUG:ERR:WRCV: Catched: An error occured while writing GitHub JSON Object to File.");  
    }
}

async function createSBOM(data) {
  const branchName = `--branch ${data.base}`;
  const filePath=`${param.CMD_SBOM}${data.sbomLocalFileName}`
  const sbomCommand = `${filePath} ${data.urlRepository} ${branchName}`;
  logDebugIfEnabled(param.APP_DEBUG, sbomCommand);

  const CMD_SBOM_TIMEOUT=param.CMD_SBOM_TIMEOUT;
  logDebugIfEnabled(param.APP_DEBUG, `DEBUG:INFO:BOM: ${new Date()} Executing SBOM tool - generating SBOM file..`);

  return await new Promise((resolve, reject) => {

    // file deepcode ignore CommandInjection: <please specify a reason of ignoring this>
    exec(sbomCommand, { CMD_SBOM_TIMEOUT }, (err, stdout, stderr) => {
      if (err) {
        const result = { 
          status: err.code, 
          msg: `INFO:ERR:BOM: Error creating SBOM file ${new Date()} for ${data.repositoryName}-${data.base} ${stderr}`,
          timestamp: `${new Date()}`,
          action: `SBOM file creating`,
          repository: data.repositoryName,
          branch: data.base,
          possibleCause: `The repository name or branch name is not exactly specified or does not exist, please check the upper and lower case.`
        };
        const jsonResult = JSON.stringify(result);
        logDebugIfEnabled(param.APP_DEBUG, jsonResult);
        reject(jsonResult);
      } else {
        logDebugIfEnabled(param.APP_DEBUG, `DEBUG:SUCCESS:BOM: BOM file created succesfully`);

        const fileSizeInBytes = fs.statSync(data.sbomLocalFileName).size;
        const result = { 
          status: 200, 
          msg: `INFO:SUCCESS:BOM: ${new Date()} SBOM file created ${data.sbomLocalFileName} ${stdout} - File Size: ${fileSizeInBytes} bytes`,
          repository: data.repositoryName,
          branch: data.base,
          action: `SBOM file created`,
          fileSizeBytes: `${fileSizeInBytes}`
        };
        const jsonResult = JSON.stringify(result);
        resolve (jsonResult);
      }
    });
  });
}

function removeSBOM(data) {
  fs.unlink(data.sbomLocalFileName, () => {
    return true;
  });
}

function readSBOM(sbomLocalFileName) {
    let fileContent;
    try {
      fileContent = fs.readFileSync(sbomLocalFileName);
      logDebugIfEnabled(param.APP_DEBUG, 'DEBUG:SUCCESS:BOM: BOM Read successfully');
    } catch (err) {
      logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:BOM: BOM Read generate the following error: ${err}`);
    }
    return fileContent;
}

async function uploadSbomToDtrack(param, data, fileContent) {
  logDebugIfEnabled(param.APP_DEBUG, `DEBUG:INFO:DTR: D. Track URL path: ${param.DTRACK_API_URL+param.DTRACK_BOM_ENDPOINT} ingesting..`);

  let formData = new FormData();
  formData.append('autoCreate', 'true');
  formData.append('projectName', data.repositoryName);
  formData.append('projectVersion', data.base);
  formData.append('bom', fileContent);

  let optionsDTrack = {
    method: 'post',
    maxBodyLength: Infinity,
    // file deepcode ignore Ssrf: <please specify a reason of ignoring this>
    url: param.DTRACK_API_URL+param.DTRACK_BOM_ENDPOINT,
    headers: {
      'Content-Type': 'multipart/form-data',
      'Accept': 'application/json',
      'X-Api-Key': param.DTRACK_API_KEY
    },
    data: formData
  }; 
  
  return axios.request(optionsDTrack)
  .then((response) => {
    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:SUCCESS:DTR: D. Track URL path: ${param.DTRACK_API_URL+param.DTRACK_BOM_ENDPOINT} ingested..`);
      const result = {
        status: response.status,
        message: `INFO:SUCCESS:DTR: ${new Date()} - Ingested DTrack SBOM file for: ${data.repositoryName} `,
        responseData: response.data
      };
      const jsonResult = JSON.stringify(result);
      return jsonResult;
  })
  .catch((error) => {
    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:DTR: D. Track URL path: ${param.DTRACK_API_URL+param.DTRACK_BOM_ENDPOINT} ingesting..`);
    let result;
    if (error.response) {
      result = {
        status: error.response.status,
        message: `INFO:ERR:DTR:  ${new Date()} - Error ingesting DTrack SBOM file for: ${data.repositoryName} info: ${error.response.data}`
      }
    } else {
      result = {
        message: `INFO:ERR:DTR:  ${new Date()} - Error ingesting DTrack SBOM file: for: ${data.repositoryName} info: ${error.message}`
      }
    }
    const jsonResult = JSON.stringify(result);
    return (jsonResult);
  });
}

async function getDTrackProject(param,data) {

  return new Promise(async (resolve, reject) => {
    try {

      param.url_project_endpoint = param.DTRACK_API_URL + param.DTRACK_PROJECT_NAME_ENDPOINT + data.repositoryName + '&version=' + data.base;
      logDebugIfEnabled(param.APP_DEBUG, `DEBUG:INFO:DT-INFO: get DTrack Project UUID URL: ${param.url_project_endpoint}`);
      
      let optionsDTrack = {
        method: 'get',
        url: param.url_project_endpoint,
        headers: {
          'X-Api-Key': param.DTRACK_API_KEY
        },
      };
      
      const response = await axios.request(optionsDTrack);
      data.projectUUID = response.data.uuid;
      
      logDebugIfEnabled(param.APP_DEBUG, `DEBUG:SUCCESS:DT-PROJ: get DTrack Project UUID: ${data.repositoryName} - UUID: ${data.projectUUID}`);
      resolve(true);
    } catch (error) {
      let result;
      if (error.response) {
        result = {
          status: error.response.status,
        };
      } else {
        result = {};
      }
      const jsonResult = JSON.stringify(result);
      reject(jsonResult);
    }
  });
}

async function getDDojoProduct(param, data) {
  try {
    let getProductOptionDDojo = {
      method: 'get',
      url: param.DDOJO_PRODUCTS_ENDPOINT + '?name_exact=' + data.repositoryName,
      headers: {
        'Authorization': `Token ${param.DDOJO_API_KEY}`
      }
    };

    const response = await axios.request(getProductOptionDDojo);

    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:SUCCESS:DD-PRO: got Product DDOJO: ${data.repositoryName} - Product id: ${response.data.results[0].id} - response status: ${response.status}`);

    return response.data.results[0].id;
  } catch (error) {
    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:DD-PRO: getting DDOJO Product: ${data.repositoryName} - ${error}`);
    return 0;
  }
}

async function getDDojoEngagement(param, data) {
  try {
    let getEngagementOptionDDojo = {
      method : 'get',
      url: param.DDOJO_ENGAGEMENTS_ENDPOINT + '?name=' + data.engagementName + '&tags=' + data.base,
      headers: {
        'Authorization': `Token ${param.DDOJO_API_KEY}`
      } 
    };   
    const response = await axios.request(getEngagementOptionDDojo);
    if (response.data.count > 0) {
      data.engagementTags = response.data.results[0].tags;
      data.engagementTargetStart = response.data.results[0].target_start;
      data.engagementTargetEnd = response.data.results[0].target_end;
      logDebugIfEnabled(param.APP_DEBUG, `DEBUG:SUCCESS:DD-ENG: got Engagement DDOJO: ${data.repositoryName} - branch: ${data.base} 
      - Engagement id: ${response.data.results[0].id} - response status: ${response.status}`);     
      data.engagementId=response.data.results[0].id;
      return response.data.results[0].id;
    } else {
      logDebugIfEnabled(param.APP_DEBUG, `DEBUG:INFO:DD-ENG: DDOJO Engagement does not exist: ${data.repositoryName} - ${response}`);
      data.engagementId=0;
      return 0;
    }
  } catch (error) {
    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:DD-ENG: getting DDOJO Engagement: ${data.repositoryName} - ${error}`);
    return 0;
  }
}

async function createDDojoProduct(param,data) {
  try {
    const API_KEY = param.DDOJO_API_KEY;

    const productDataPost = {
      name: data.repositoryName,
      description: param.DDOJO_PRO_DESC_DEFAULT,
      prod_type: param.DDOJO_PRO_TYPE_DEFAULT,
      enable_simple_risk_acceptance: 'True',
      enable_full_risk_acceptance: 'True',
      tags: [
        "dependency"
      ],
     };
    //   TODO: Jira configurations to Add: 'PATCH' 'https://dojo.staging.bfainfra.com/api/v2/jira_product_configurations

    let createProOptionDDojo = {
      method : 'post',
      url: param.DDOJO_PRODUCTS_ENDPOINT,
      headers: {
        'Authorization': `Token ${API_KEY}`,
        'Content-Type': 'application/json',
      },
      data: productDataPost
    };
    const response = await axios.request(createProOptionDDojo);
    data.productId = response.data.id;
    const result = { 
      status: response.status, 
      msg: `INFO:SUCCESS:DD-PRO: ${new Date()} Product name: ${data.repositoryName} id: ${data.productId} created`,
      repository: data.repositoryName,
      product_url: param.DDOJO_PRODUCT_URL + data.productId,
      action: `Product created`
    };
    const jsonResult = JSON.stringify(result);
    console.log(jsonResult);
    return (data.productId);
  } catch (error) {
    let result = null;
    if (error.response) {
      logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:DD-PRO: Error creating DDojo product: ${data.repositoryName} - ${error.response.data}`);    

      result = { 
        status: error.status, 
        msg: `INFO:ERR:DD-PRO: ${new Date()} Error creating DDojo Product ${data.repositoryName} error data: ${error.response.data}`,
        action: `Product creating..`
      };
    } else {
      result = { 
        status: error.status, 
        msg: `INFO:ERR:DD-PRO: ${new Date()} Error creating DDojo Product ${data.repositoryName} error message ${error.message}`,
        action: `Product creating..`
      };
    }
    const jsonResult = JSON.stringify(result);
    console.log(jsonResult);
    return (error);
  }
} 

async function createDDojoEngagement(param,data) {
  try {
    const API_KEY = param.DDOJO_API_KEY;
    const createEngDataPost = {
      product: data.productId,
      tags: [
        data.base
      ],
      name: data.engagementName,
      target_start: param.DDOJO_ENG_TARGET_START,
      target_end: param.DDOJO_ENG_TARGET_END,
      active: "True",
      status: 'In Progress',
      engagement_type: "Interactive",
      status: "In Progress",
      source_code_management_uri: param.GH_URL_ORG + data.repositoryName,
      deduplication_on_engagement: "True"
    };
    
    if (data.base == data.defaultBranch) {
      createEngDataPost.tags.push("default");
    }

    let createEngOptionDDojo = {
      method : 'POST',
      url: param.DDOJO_ENGAGEMENTS_ENDPOINT,
      headers: {
        'Authorization': `Token ${API_KEY}`,
        'Content-Type': 'application/json',
      },
      data: createEngDataPost
    };

    const response = await axios.request(createEngOptionDDojo);
    data.engagementId = response.data.id;
    const result = { 
      status: response.status, 
      msg: `INFO:SUCCESS:DD-ENG: ${new Date()} Engagement name: ${data.engagementName} - branch: ${data.base} id: ${data.engagementId} created for ${data.repositoryName}`,
      repository: data.repositoryName,
      branch: data.base,
      engagement_name: data.engagementName,
      engagement_id: data.engagementId,
      engagement_url: param.DDOJO_ENGAGEMENT_URL + data.engagementId,
      action: `Engagement created`,
      tags: createEngDataPost.tags
    };
    const jsonResult = JSON.stringify(result);
    console.log(jsonResult);
    return (data.engagementId);
  } catch (error) {
    let result = null;
    if (error.response) {
      logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:DD-ENG: Error creating DDojo engagement: ${data.repositoryName} - branch: ${data.base} - ${error.response.data}`);    

      result = { 
        status: error.status, 
        msg: `INFO:SUCCESS:DD-ENG: ${new Date()} Error creating DDojo engagement: ${data.engagementName} - branch: ${data.base} for ${data.repositoryName} ${error.response.data}`,
        action: `Engagement creating..`
      };
    } else {
      result = { 
        status: error.status, 
        msg: `INFO:SUCCESS:DD-ENG: ${new Date()} Error creating DDojo engagement: ${data.engagementName} - branch: ${data.base} for ${data.repositoryName} ${error.message}`,
        action: `Engagement creating..`
      };
    }    
    const jsonResult = JSON.stringify(result);
    console.log(jsonResult);
    return (error);
  }
} 


async function updateDDojoEngagement(param,data) {
  try {
    const API_KEY = param.DDOJO_API_KEY;

    const updEngTagDataPost = {
      product: data.productId,
      tags: data.engagementTags,
      target_start: data.engagementTargetStart, 
      target_end: data.engagementTargetEnd
     };

    let updateEngTagOptionDDojo = {
      method : 'PATCH',
      url: param.DDOJO_ENGAGEMENTS_ENDPOINT + data.engagementId + "/",
      headers: {
        'Authorization': `Token ${API_KEY}`,
        'Content-Type': 'application/json',
      },
      data: updEngTagDataPost
    };

    const isDefaultBranchPresent = data.engagementTags.includes(data.defaultBranch);
    if (isDefaultBranchPresent && !data.engagementTags.includes("default") ) {
      updEngTagDataPost.tags.push("default");
      const response = await axios.request(updateEngTagOptionDDojo);

      const result = {
        status: response.status, 
        msg: `INFO:SUCCESS:DD-ENG: ${new Date()} Engagement name: ${data.engagementName} - branch: ${data.base} id: ${data.engagementId} updated - added 'default' tag for ${data.repositoryName}`,
        repository: data.repositoryName,
        branch: data.base,
        engagement_name: data.engagementName,
        engagement_id: data.engagementId,
        engagement_url: param.DDOJO_ENGAGEMENT_URL + data.engagementId,
        action: `Engagement updated`,
        tags: updEngTagDataPost.tags
      };
      const jsonResult = JSON.stringify(result);
      console.log(jsonResult);
      return (data.engagementId);
    } else {
      if (!isDefaultBranchPresent && data.engagementTags.includes("default")) {
        // remove default tag from the list of tags
        updEngTagDataPost.tags = updEngTagDataPost.tags.filter(tag => tag !== "default");
        const response = await axios.request(updateEngTagOptionDDojo);
        const result = {
          status: response.status, 
          msg: `INFO:SUCCESS:DD-ENG: ${new Date()} Engagement name: ${data.engagementName} - branch: ${data.base} id: ${data.engagementId} updated - removed 'default' tag for ${data.repositoryName}`,
          repository: data.repositoryName,
          branch: data.base,
          engagement_name: data.engagementName,
          engagement_id: data.engagementId,
          engagement_url: param.DDOJO_ENGAGEMENT_URL + data.engagementId,
          action: `Engagement updated`,
          tags: updEngTagDataPost.tags
        };
        const jsonResult = JSON.stringify(result);
        console.log(jsonResult);
        return (data.engagementId);        
      }
    }
  } catch (error) {
    let result = null;
    if (error.response) {
      logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:DD-ENG: Error updating DDojo engagement: ${data.repositoryName} - branch: ${data.base} - ${error.response.data}`);    

      result = { 
        status: error.status, 
        msg: `INFO:ERR:DD-ENG: ${new Date()} Error updating DDojo engagement: ${data.engagementName} - branch: ${data.base} for ${data.repositoryName} ${error.response.data}`,
        action: `Engagement updating..`
      };
    } else {
      result = { 
        status: error.status, 
        msg: `INFO:ERR:DD-ENG: ${new Date()} Error updating DDojo engagement: ${data.engagementName} - branch: ${data.base} for ${data.repositoryName} ${error.message}`,
        action: `Engagement updating..`
      };
    }    
    const jsonResult = JSON.stringify(result);
    console.log(jsonResult);
    return (error);
  }
} 


async function createDTrackIntegration(param,data) {

    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:INFO:DT-PROP: DTrack integration DDojo:  ${data.projectUUID} - Engagement Id: ${data.engagementId}`);
    param.url_project_prop_endpoint=param.DTRACK_API_URL+param.DTRACK_PROJECT_PROP_ENDPOINT + data.projectUUID + '/property';

    const updatePropertiesOptions = {
      groupName: param.DTRACK_INTEGRA_GROUPNAME,
      propertyName: param.DTRACK_INTEGRA_PROPERTYNAME,
      propertyValue: data.engagementId,
      propertyType: param.DTRACK_INTEGRA_PROPERTY_TYPE
     };
     const createPropertiesOptions = {
      project: {
        uuid: data.projectUUID
      },
      groupName: param.DTRACK_INTEGRA_GROUPNAME,
      propertyName: param.DTRACK_INTEGRA_PROPERTYNAME,
      propertyValue: data.engagementId,
      propertyType: param.DTRACK_INTEGRA_PROPERTY_TYPE
     };

    let getOptionsDTrack = {
      method : 'get',
      url: param.url_project_prop_endpoint,
      headers: {
        'X-Api-Key': param.DTRACK_API_KEY
      }
    }; 

    let createOptionsDTrack = {
      method : 'PUT',
      // file deepcode ignore Ssrf: <please specify a reason of ignoring this>
      maxBodyLength: Infinity,
      url: param.url_project_prop_endpoint,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Api-Key': param.DTRACK_API_KEY
      },
      data: createPropertiesOptions
    }; 

    let updateOptionsDTrack = {
      method : 'POST',
      maxBodyLength: Infinity,
      url: param.url_project_prop_endpoint,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Api-Key': param.DTRACK_API_KEY
      },
      data: updatePropertiesOptions
    }; 

    let response = await axios.request(getOptionsDTrack);

    //  TOBE CONTINUED: validar si existe la Integración en DTRACK
    if (response.data.length === 0) {
      //Create DTRACK Integration
      response = await axios.request(createOptionsDTrack);
      const result = {
        status: response.status,
        msg: `INFO:SUCCESS:DT-PROP: ${new Date()} - Created DTrack Integration Properties for: ${data.repositoryName} new engagementId: ${data.engagementId}`,
        action: `DTrack integration created`,
        timestamp: `${new Date()}`,
        repository: data.repositoryName,
        branch: data.base,
        engagement_id: data.engagementId,
        engagement_name: data.engagementName,
        project_url: param.DTRACK_PROJECTS_URL + data.projectUUID,
        responseData: response.data
      };       
      const jsonResult = JSON.stringify(result);
      console.log(jsonResult);
      return result;
    } else {
      if (response.data[0].groupName == param.DTRACK_INTEGRA_GROUPNAME 
        && response.data[0].propertyName == param.DTRACK_INTEGRA_PROPERTYNAME 
        && response.data[0].propertyValue != data.engagementId.toString()){
         // Update DTRACK Integration
         response = await axios.request(updateOptionsDTrack);
         const result = {
           status: response.status,
           timestamp: `${new Date()}`,
           msg: `INFO:SUCCESS:DT-PROP: ${new Date()} - Updated DTrack Integration Properties for: ${data.repositoryName}`,
           action: `DTrack integration updated`,
           repository: data.repositoryName,
           branch: data.base,
           engagement_id: data.engagementId,
           engagement_name: data.engagementName,
           project_url: param.DTRACK_PROJECTS_URL + data.projectUUID,
           responseData: response.data
         };
         const jsonResult = JSON.stringify(result);
         console.log(jsonResult);
         return result;
      }
    }
}

function logDebugIfEnabled(isDebugMode, ...messages) {
  if (isDebugMode === 'true') {
    console.log(...messages);
  }
}

app.post('/webhook', async function (req, res) {

  const data=getWebhookData(req,  param.HEADER_EVENT, param.HEADER_CONTENT_TYPE);

  if (validate.validateWebhookRequest(param, data, res)) {
    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:SUCCESS:VAL_JSON_KEYS: Json Keys Structure are Ok. Parameters: ${param.HEADER_EVENT} - ${param.HEADER_CONTENT_TYPE}`);

    if (validate.validateRequestBody(param, data)) {

      let jsonDataStr = JSON.stringify(data.jsonData, null, 2);
      let nameFileGH='';

      Boolean(param.MOD_W_RCV_GH_ENABLED)=='true'
        ? (
          nameFileGH = `temp/my_sbom_files/${param.GH_PREFIX_FILE}${data.repositoryName}${param.STR_SEPARATOR}${data.number}${param.JSON_EXTENSION}`,
          writePayloadToJsonFile(nameFileGH, jsonDataStr)
        )
       : null;

      data.sbomLocalFileName = `temp/my_sbom_files/${param.BOM_PREFIX_FILE}${data.repositoryName}${param.STR_SEPARATOR}${data.number}${param.JSON_EXTENSION}`;
      res.status(201).send(`Received and Processing`);

      createSBOM(data)
      .then(async (stdout) => {
        console.log(stdout);
        const fileContent = readSBOM(data.sbomLocalFileName);
        data.sbomFileName = `${param.BOM_PREFIX_FILE}${data.repositoryName}${param.JSON_EXTENSION}`;

        await getDTrackProject(param,data);
        
        uploadSbomToDtrack(param, data, fileContent)
        .then(async (response) => {

          data.productId = await getDDojoProduct(param, data);
          data.engagementName = param.DDOJO_ENG_PREFIX + data.repositoryName;

          //  Product exists
          if (data.productId > 0) {
            await getDDojoEngagement(param,data);
            //  Engagement exists
            if (data.engagementId == 0) {
              await createDDojoEngagement(param,data);
            } else {
              await updateDDojoEngagement(param,data);
            }
          } else {
            await createDDojoProduct(param,data);
            await createDDojoEngagement(param,data);
          }
          await createDTrackIntegration(param,data);
        })
        .catch((err) => {
          console.log (`INFO:ERR:DT-UPL: ${err}`);
        })
        removeSBOM(data);
      })
      .catch(err => {
        console.log(err); 
        res.end();
      });
    } else {
      return res.status(200).send({ info: `DEBUG:ERR:VAL_JSON_VALUES: JSON values are invalid or skipped repository ${data.repositoryName}` })
    }   
  } else {
    logDebugIfEnabled(param.APP_DEBUG, `DEBUG:ERR:VAL_JSON_KEYS:  JSON key structure are invalid. ${data.repositoryName} repo 
      -Event:${data.event} -ContentType:${data.contentType} -Action:${data.action} -State:${data.state} 
      -Base:${data.base} -Merged:${data.merged} -Number:${data.number} -URL:${data.urlRepository}`);

    return res.status(200).send({ error: `DEBUG:ERR:VAL_JSON_KEYS: JSON key structure are invalid ${data.repositoryName} repo 
    -Event:${data.event} -ContentType:${data.contentType} -Action:${data.action} -State:${data.state} 
    -Base:${data.base} -Merged:${data.merged} -Number:${data.number} 
    -URL:${data.urlRepository}`})
  }
});

const newLocal = 'uncaughtException';
  process.on(newLocal, (error) => {
    const jsonError = JSON.stringify(error);
    console.error(`GENERAL:CRITICAL:ERR: Caught exception: ${jsonError}`);
});

app.listen(param.APP_PORT, () => {
  logDebugIfEnabled(param.APP_DEBUG, "Server running on port:", param.APP_PORT);
});
