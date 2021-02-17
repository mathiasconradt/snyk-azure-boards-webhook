// index.js
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const PORT = process.env.PORT || 5000;
const ISSUE_TEMPLATE = [
  {
    "op": "add",
    "path": "/fields/System.Title",
    "from": null,
    "value": null
  },
  {
    "op": "add",
    "path": "/fields/System.Description",
    "from": null,
    "value": null
  },
{
    "op": "add",
    "path": "/fields/System.WorkItemType",
    "from": null,
    "value": "Issue"
  }
];

const app = express()
  .use(bodyParser.urlencoded({ extended: true }))
  .use(bodyParser.json())
  .use(bodyParser.raw())
  .get('/snyk', (req, res) => {

    var x = {};
    var y = _.clone(x);

    console.log('process.env.AZURE_DEVOPS_USER ' + process.env.AZURE_DEVOPS_USER);
    res.sendStatus(200);
  })
  .post('/snyk', (req, res) => {
      console.log('Got body:', req.body);

      var verified = this.verifySignature(req);
      console.log('verified: ', verified);

      if (verified && req.body.newIssues) {
        var newIssues = req.body.newIssues;
        newIssues.forEach(issue => {        
          var it = JSON.parse(JSON.stringify(ISSUE_TEMPLATE));
          it[0].value = issue.issueData.title + " [" + issue.issueData.id + "]";
          it[1].value = issue.issueData.description;
          this.createIssuePostman(it);
        });
      }
      res.sendStatus(200);
  })
  .listen(PORT, () => console.log(`Listening on ${ PORT }`));

module.exports.verifySignature = function (request) {
  const hmac = crypto.createHmac( 'sha256' , process.env.SNYK_WEBHOOKS_SECRET);
  const buffer = JSON .stringify(request.body);
  hmac.update(buffer, 'utf8' );
  const signature = `sha256=${hmac.digest('hex')}` ;
  return signature === request.headers[ 'x-hub-signature' ];
}

module.exports.createIssuePostman = function(issue) {
  console.log('createIssuePostman: ' + issue[0].value);
  var auth = 'Basic ' + Buffer.from(process.env.AZURE_DEVOPS_USER + ':' + process.env.AZURE_DEVOPS_ACCESS_TOKEN).toString('base64');
  var config = {
    method: 'post',
    url: 'https://dev.azure.com/' + process.env.AZURE_DEVOPS_ORGANIZATION + '/' + process.env.AZURE_DEVOPS_PROJECT + '/_apis/wit/workitems/$Issue?validateOnly=false&api-version=6.0',
    headers: {       
      'Authorization': auth,
      'Content-Type': 'application/json-patch+json'
    },
    data : issue
  };
  axios(config)
  .then(function (response) {
    console.log(JSON.stringify(response.data));
  })
  .catch(function (error) {
    console.log("*** Error ***");
    console.log(error);
  });
}
