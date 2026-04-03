export function validateWebhookRequest(param, data, res) {

    if (typeof data.event === 'undefined' || typeof data.contentType==='undefined' || typeof data.action === 'undefined' || typeof data.state === 'undefined'
      || typeof data.base === 'undefined' || typeof data.merged === 'undefined'
      || typeof data.jsonData === 'undefined' || typeof data.number === 'undefined' || typeof data.urlRepository === 'undefined'
      || typeof data.repositoryName === 'undefined' ) {
        return false;
    } else {
      return true;
    }
  }

export function validateRequestBody(param, data, res) {
    let valuesGHBASE = param.GH_BASE.split(',');
    let valuesGHMERGED = param.GH_MERGED.split(',');
    let valuesSKIPREPO = param.DSABOT_SKIP_REPO.split(',');
  
    try {
      // Validate if header and body values are OK
      if (data.event == param.GH_EVENT
          && data.contentType == param.GH_CONTENT_TYPE
          && data.action == param.GH_ACTION
          && data.state == param.GH_STATE
          && valuesGHBASE.includes(data.base)
          && valuesGHMERGED.includes(data.merged)
          && !valuesSKIPREPO.includes(data.repositoryName)
        ) {
        
        param.APP_DEBUG=='true' ? console.log(`DEBUG:SUCCESS:VAL_JSON_VALUES: Json Keys Structure are OK`) : null;
        return true;
      } else {

        param.APP_DEBUG=='true' ? console.log(`DEBUG:ERR:VAL_JSON_VALUES: Json Keys Structure are invalid or skipped repository - ${data.repositoryName}-
        ${data.event}-${param.GH_EVENT};
        ${data.contentType}-${param.GH_CONTENT_TYPE};
        ${data.action}-${param.GH_ACTION};  
        ${data.state}-${param.GH_STATE};
        ${data.base}-${valuesGHBASE};
        ${data.merged}-${valuesGHMERGED};
        ${data.repositoryName}<>${param.DSABOT_SKIP_REPO}`) : null;

        return false;
      }
    } catch (err) {
      param.APP_DEBUG=='true' ? console.log(`DEBUG:ERR:VAL_JSON_VALUES: error catched: Json Keys Structure are invalid`) : null;

      return false;
    }
  }
