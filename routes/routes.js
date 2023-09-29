const express = require('express');
const router = express.Router();
const dns = require('dns');
const whois = require('whois-json');
const lookup = require('dnsbl-lookup');
const fs = require('fs');
const stream = require('stream');
const { log } = require('console');
const axios = require('axios');
const puppeteer = require('puppeteer')
const { google } = require('googleapis');
const { Readable } =  require('stream')
const https = require('https');
const validator = require('validator');

// Load the service account key file (replace with your own key file)
const serviceAccountKey = require('./secrets.json');

// Create a JWT client using the service account credentials
const jwtClient = new google.auth.JWT(
  serviceAccountKey.client_email,
  null,
  serviceAccountKey.private_key,
  ['https://www.googleapis.com/auth/drive']
);

// Set up the Google Drive API
const drive = google.drive({ version: 'v3', auth: jwtClient });


async function captureScreenshotAndUpload(url) {
  try {
    // Capture the screenshot using Puppeteer
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto(url);
    const screenshotBuffer = await page.screenshot({ encoding: 'basr64' });
    await browser.close();

    // Upload the screenshot to Google Drive
    const fileMetadata = {
      name: 'screenshot.png', // Change the filename as needed
    };

    const media = {
      mimeType: 'image/jpeg', // Change the MIME type as needed
      body:Readable.from(Buffer.from( screenshotBuffer, 'base64')), 
    };

    const uploadedFile = await drive.files.create({
      resource: fileMetadata,
      media: media,
      fields: 'id',
    });

    // Set permissions for the uploaded file
    const permission = {
      type: 'anyone',
      role: 'reader',
    };

    await drive.permissions.create({
      fileId: uploadedFile.data.id,
      requestBody: permission,
    });

    // Construct the URL of the uploaded image
    const imageUrl = `https://drive.google.com/uc?id=${uploadedFile.data.id}`;

    return imageUrl;
  } catch (error) {
    console.error('Error capturing and uploading screenshot:', error);
    return "";
  }
}
// Function to fetch rDNS records for a domain name
async function fetchRdnsRecords(domainName) {
  try {
    const ipAddress = await dns.promises.resolve(domainName);
    const rdnsRecords = await dns.promises.reverse(ipAddress[0]);
    console.log(`rDNS records for ${domainName}:`, rdnsRecords);
    return { domain: domainName, rdnsRecords };
  } catch (error) {
    console.error(`Error fetching rDNS records for ${domainName}: ${error.message}`);
    return { domain: domainName, rdnsRecords: [] };
  }
}


// Function to fetch BIMI record for a domain with error logging and a timeout
async function fetchBimiRecord(domain, timeoutMs = 4000) {
  return new Promise(async (resolve) => {
    const timer = setTimeout(() => {
      console.log('DNS query timed out for', domain);
      resolve([]);
    }, timeoutMs);

    try {
      const bimiRecords = await dns.promises.resolveTxt(`default._bimi.${domain}`);
      clearTimeout(timer);
       console.log(bimiRecords);
      // Filter BIMI records that match the "v=BIMI1;" format
      const validBimiRecords = bimiRecords.filter(record => record[0].includes("v=BIMI1;"));
      console.log(validBimiRecords);
      if (validBimiRecords.length > 0) {
        resolve(validBimiRecords);
      } else {
        console.error(`Valid BIMI Record not found for ${domain}`);
        resolve([]);
      }
    } catch (error) {
      clearTimeout(timer);
      resolve([]);
    }
  });
}

async function checkDomainBlacklist(domain, blocklistArray, timeoutMs) {
  return new Promise((resolve, reject) => {
    const uribl = new lookup.uribl([domain], blocklistArray);
    const result = {};
    let timedOut = false; // Flag to track if a timeout occurred

    // Handle errors during the blacklist check
    uribl.on('error', function (err, bl) {
      console.error(`Error checking blocklist ${bl} for ${domain}: ${err}`);
    });

    // Handle data received from the blacklist check
    uribl.on('data', function (response, bl) {
      result[bl] = response;
    });

    // Handle completion of the blacklist check
    uribl.on('done', function () {
      if (!timedOut) {
        // If the check completed before the timeout, resolve with the result
        resolve(result);
      }
    });

    // Set a timeout for the blacklist check
    setTimeout(() => {
      timedOut = true;
      
      reject(new Error(`Timeout exceeded (${timeoutMs}ms) while checking domain blacklist for ${domain}`));
    }, timeoutMs);
  });
}

// Function to fetch DKIM records for a domain with a specific selector
async function fetchAllDkimRecords(domain, selector) {
  try {
    const dkimSubdomain = `${selector}._domainkey.${domain}`;
    const txtRecords = await dns.promises.resolveTxt(dkimSubdomain);

    // Filter and parse DKIM records (if multiple exist)
    const dkimRecords = txtRecords
      .map(record => {
        const dkimRecord = {};
        const keyValuePairs = record[0].split(';');

        for (const pair of keyValuePairs) {
          const [key, value] = pair.split('=');
          if (key && value) {
            dkimRecord[key.trim()] = value.trim();
          }
        }

        // Check if the necessary DKIM properties exist
        if (dkimRecord.v && dkimRecord.k) {
          return dkimRecord;
        }

        return null; // Skip records that don't have the required properties
      })
      .filter(record => record !== null);

    return dkimRecords;
  } catch (error) {
     return [];
  }
}

// Function to fetch MX records for a domain
async function fetchMxRecords(domain) {
  try {
    const mxRecords = await dns.promises.resolveMx(domain);
    console.log("MX fetching success!!");
    return mxRecords;
  } catch (error) {
    return [];
  }
}

// Function to fetch SPF records for a domain
async function fetchSpfRecords(domain) {
  try {
    const txtRecords = await dns.promises.resolveTxt(domain);
    const spfRecords = txtRecords.filter(record => record[0].startsWith('v=spf1'));
    console.log("SPF Fetching!!");
    return spfRecords;
  } catch (error) {
     return [];
  }
}

// Function to fetch DMARC records for a domain
async function fetchDmarcRecords(domain) {
  try {
    const dmarcSubdomain = '_dmarc.' + domain;
    const txtRecords = await dns.promises.resolveTxt(dmarcSubdomain);
    console.log("DMARC fetching!!");
    return txtRecords;
  } catch (error) {
    return [];
  }
}



// Function to check HTTP support for a single domain
async function checkHttpSupport(domain) {
  try {
    const response = await axios.head(`http://${domain}`, { timeout: 5000 });

    if (response.status === 200) {
      return true; // HTTP is supported
    } else if (response.status === 405) {
      console.warn(`HTTP request error for ${domain}: Method Not Allowed (Status Code 405)`);
      return `HTTP request error for ${domain}: Method Not Allowed (Status Code 405)` ;
    } else {
      console.error(`HTTP request error for ${domain}: Unexpected Status Code ${response.status}`);
      return `HTTP request error for ${domain}: Unexpected Status Code ${response.status}`;
    }
  } catch (error) {
    console.error(`HTTP request error for ${domain}: ${error.message}`);
    return `HTTP request error for ${domain}: ${error.message}`;
  }
}

async function fetchDomainInfo(domain) {
  try {
    const whoisData = await whois(domain);

    const creationDate = whoisData.creationDate;
    const registrar = whoisData.registrar;

    if (!creationDate || !registrar) {
      return {
        registrar: '',
        creationDate: '',
        ageInDays: '',
      };
    }

    // Calculate domain age
    const currentDate = new Date();
    const ageInMilliseconds = currentDate - new Date(creationDate);
    const ageInDays = Math.floor(ageInMilliseconds / (1000 * 60 * 60 * 24));

    return {
      registrar: registrar,
      creationDate: creationDate,
      ageInDays: ageInDays,
    };
  } catch (error) {
    throw error;
  }
}

// Function to check HTTPS support for a single domain
async function checkHttpsSupport(domain) {
  try {
    const response = await axios.head(`https://${domain}`, { timeout: 7000 });

    if (response.status === 200) {
      return true; // HTTPS is supported
    } else if (response.status === 405) {
      console.warn(`HTTPS request error for ${domain}: Method Not Allowed (Status Code 405)`);
      return `HTTPS request error for ${domain}: Method Not Allowed (Status Code 405)`;
    } else {
      console.error(`HTTPS request error for ${domain}: Unexpected Status Code ${response.status}`);
      return `HTTPS request error for ${domain}: Unexpected Status Code ${response.status}`;
    }
  } catch (error) {
    console.error(`HTTPS request error for ${domain}: ${error.message}`);
    return `HTTPS request error for ${domain}: ${error.message}`;
  }
}


async function checkDomainForwarding(domain) {
  try {
    const response = await axios.get(`http://${domain}`, {
      maxRedirects: 0,
      validateStatus: (status) => status === 301 || status === 302,timeout:1000
    });

    if (response.headers['location']) {
      return {
        isForwarding: true,
        forwardingTo: response.headers['location'],
      };
    } else {
      return {
        isForwarding: false,
      };
    }
  } catch (error) {
    console.error(`Error checking domain forwarding for ${domain}: ${error.message}`);
    return  {
      isForwarding: false,
    };
    
    
  }
}





// Function to fetch TLS-RPT (TLS Reporting Policy and Trust) records for a domain
async function fetchTlsRptRecord(domain) {
  try {
    const tlsRptSubdomain = '_smtp._tls.' + domain;
    const records = await dns.promises.resolveTxt(tlsRptSubdomain);
    // console.log(records);
    // Check if the records are in the correct format (v=TLSRPTv1)
    const validRecords = records. filter(record => record[0].includes("v=TLSRPTv1;"));
     console.log(validRecords);
    if (validRecords.length > 0) {
      console.log("TLSRPT records found:", validRecords);
      return validRecords;
    } else {
      console.error("Invalid or missing TLSRPT records for", domain);
      return [];
    }
  } catch (error) {
    console.error(`Error fetching TLSRPT records for ${domain}: ${error.message}`);
    return [];
  }
}

async function fetchDomainInfoWithTimeout(domain, timeoutMs) {
  try {
    return await Promise.race([
      fetchDomainInfo(domain),
      new Promise((_, reject) => {
        setTimeout(() => {
          reject(new Error('Domain info fetch timed out'));
        }, timeoutMs);
      }),
    ]);
  } catch (error) {
    console.error(`Error fetching domain info for ${domain}: ${error.message}`);
    return {
      registrar: '',
      creationDate: '',
      ageInDays: '',
      error: `Error fetching domain info: ${error.message}`,
    };
  }
}


async function fetchNameServersWithTimeout(domain, timeoutMilliseconds) {
  return new Promise(async (resolve, reject) => {
    const timeoutId = setTimeout(() => {
      clearTimeout(timeoutId);
      reject(new Error('Name server lookup timed out.'));
    }, timeoutMilliseconds);

    try {
      const nameServers = await new Promise((innerResolve, innerReject) => {
        dns.resolveNs(domain, (err, nsRecords) => {
          if (err) {
            innerReject(err);
          } else {
            innerResolve(nsRecords);
          }
        });
      });

      clearTimeout(timeoutId); // Clear the timeout if the lookup succeeded
      resolve(nameServers);
    } catch (error) {
      clearTimeout(timeoutId); // Clear the timeout if an error occurred
      resolve([]); // Return an empty array if there was an error
    }
  });
}


// Function to fetch A (IPv4) records for a domain
async function fetchARecords(domain) {
  try {
    const addresses = await dns.promises.resolve4(domain);
    console.log('A record fetch success');
    return addresses;
  } catch (error) {
    console.log('A record fetch error');
    return [];
  }
}

// Function to fetch AAAA (IPv6) records for a domain
async function fetchAAAARecords(domain) {
  try {
    const addresses = await dns.promises.resolve6(domain);
    console.log('AAA record fetch success');
    return addresses;
  } catch (error) {
    console.log('AAA record fetch error');
    return [];
  }
}

// Function to discover specific subdomains for a domain
async function discoverSubdomains(domain) {
  const subdomainsToCheck = ['shop','www', 'mail', 'ftp', 'blog', 'test','status','link','remote']; // Add the subdomains you want to check here
  const discoveredSubdomains = [];

  for (const subdomain of subdomainsToCheck) {
    try {
      // Check A records
      const aSubdomain = `${subdomain}.${domain}`;
      const aRecords = await fetchARecords(aSubdomain);
      if (aRecords.length > 0 && !discoveredSubdomains.includes(aSubdomain)) {
        discoveredSubdomains.push(aSubdomain);
      }

      // Check AAAA records
      const aaaaSubdomain = `${subdomain}.${domain}`;
      const aaaaRecords = await fetchAAAARecords(aaaaSubdomain);
      if (aaaaRecords.length > 0 && !discoveredSubdomains.includes(aaaaSubdomain)) {
        discoveredSubdomains.push(aaaaSubdomain);
      }
    } catch (error) {
      return [];
    }
  }
 console.log("subdomain check!!");
  return discoveredSubdomains;
}

// Function to fetch MTA-STS records for a domain
async function fetchMtaSts(domain) {
  try {
    const mtaStsSubdomain = `_mta-sts.${domain}`;
    const txtRecords = await dns.promises.resolveTxt(mtaStsSubdomain);
    console.log(txtRecords);
    // Filter MTA-STS records based on the presence of "v=STSv1;"
    const validMtaStsRecords = txtRecords.filter(record => record[0].includes("v=STSv1;"));
    console.log(validMtaStsRecords);
    return validMtaStsRecords;
  } catch (error) {
    return [];
  }
}

router.post('/mx',async(req,res)=>{
  const {domains} = req.body;

  try {
    const mxRecordsPromises = domains.map((domain) => fetchMxRecords(domain));
    const mxRecords = await Promise.all(mxRecordsPromises);

    // Combine the domains and their MX records into an array of objects
    const domainMXPairs = domains.map((domain, index) => ({
      domain,
      mxRecords: mxRecords[index],
    }));

    res.json(domainMXPairs);
  } catch (error) {
    console.error(`Error fetching MX records: ${error.message}`);
    res.status(500).json({ error: 'An error occurred while fetching MX records.' });
  }
})

router.post('/spf',async(req,res) => {
  const {domains} = req.body;
  try {
    const spfRecordsPromises = domains.map((domain) => fetchSpfRecords(domain));
    const spfRecords = await Promise.all(spfRecordsPromises);

    // Combine the domains and their SPF records into an array of objects
    const domainSPFPairs = domains.map((domain, index) => ({
      domain,
      spfRecords: spfRecords[index],
    }));

    res.json(domainSPFPairs);
  } catch (error) {
    console.error(`Error fetching SPF records: ${error.message}`);
    res.status(500).json({ error: 'An error occurred while fetching SPF records.' });
  }
})

router.post('/dmarc',async(req,res)=> {
  const{domains} = req.body;
  try {
    const dmarcRecordsPromises = domains.map((domain) => fetchDmarcRecords(domain));
    const dmarcRecords = await Promise.all(dmarcRecordsPromises);

    // Combine the domains and their DMARC records into an array of objects
    const domainDMARCPairs = domains.map((domain, index) => ({
      domain,
      dmarcRecords: dmarcRecords[index],
    }));

    res.json(domainDMARCPairs);
  } catch (error) {
    console.error(`Error fetching DMARC records: ${error.message}`);
    res.status(500).json({ error: 'An error occurred while fetching DMARC records.' });
  }
})

router.post('/ns', async (req, res) => {
  const { domains } = req.body;
  try {
    const nsRecordsPromises = domains.map((domain) => fetchNameServersWithTimeout(domain, 3000));
    const nsRecords = await Promise.allSettled(nsRecordsPromises);

    // Process the results of all promises, including both fulfilled and rejected promises
    const domainNSPairs = nsRecords.map((result, index) => {
      if (result.status === 'fulfilled') {
        return {
          domain: domains[index],
          nsRecords: result.value,
        };
      } else {
        // Handle the error for the rejected promise
        console.error(`Error fetching NS records for ${domains[index]}: ${result.reason.message}`);
        return {
          domain: domains[index],
          nsRecords: [],
          error: result.reason.message,
        };
      }
    });

    res.json(domainNSPairs);
  } catch (error) {
    console.error(`Error fetching NS records: ${error.message}`);
    res.status(500).json({ error: 'An error occurred while fetching NS records.' });
  }
});

router.post('/subdomains', async (req, res) => {
  const { domains } = req.body;
  try {
    const subdomainsArray = [];

    for (const domain of domains) {
      const subdomains = await discoverSubdomains(domain);
      subdomainsArray.push({ domain, subdomains });
    }

    res.json({ subdomainsArray });
  } catch (error) {
    console.error('Error fetching subdomains:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Define a route to fetch rDNS records
router.post('/rdns', async (req, res) => {
  const { domains } = req.body;


  try {
    const rdnsRecords = await Promise.all(domains.map(fetchRdnsRecords));
    res.json({ rdnsRecords });
  } catch (error) {
    console.error(`Error fetching rDNS records: ${error.message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Define the route for performing the checkhttp operation for an array of domains
router.post('/checkhttp', async (req, res) => {
  const { domains } = req.body;

  try {
    const results = await Promise.all(domains.map(checkHttpSupport));
    const domainHttpSupportPairs = domains.map((domain, index) => ({
      domain,
      httpSupported: results[index],
    }));
    
    res.json({ domainHttpSupportPairs });
  } catch (error) {
    console.error('Error performing checkhttp:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Define the route for performing the checkhttp operation for an array of domains
router.post('/checkhttps', async (req, res) => {
  const { domains } = req.body;

  try {
    const results = await Promise.all(domains.map(checkHttpsSupport));
    const domainHttpSupportPairs = domains.map((domain, index) => ({
      domain,
      httpsSupported: results[index],
    }));
    
    res.json({ domainHttpSupportPairs });
  } catch (error) {
    console.error('Error performing checkhttp:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/domainInfo', async (req, res) => {
  const { domains, timeoutMs } = req.body;
  try {
    const domainInfoPromises = domains.map((domain) => fetchDomainInfoWithTimeout(domain,6000));
    const domainInfoResults = await Promise.all(domainInfoPromises);

    // Combine the domains and their info results into an array of objects
    const domainInfoPairs = domains.map((domain, index) => ({
      domain,
      info: domainInfoResults[index],
    }));

    res.json({ domainInfoPairs });
  } catch (error) {
    console.error('Error fetching domain info:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Define the route for performing a blacklist check
router.post('/blacklist', async (req, res) => {
  const { domains } = req.body;

  try {
    const blacklist = [
      'all.s5h.net',		
      'blacklist.woody.ch',	'bogons.cymru.com',	'cbl.abuseat.org',
      'combined.abuse.ch' ,	'db.wpbl.info'	,'dnsbl-1.uceprotect.net',
      'dnsbl-2.uceprotect.net',	'dnsbl-3.uceprotect.net',	'dnsbl.dronebl.org',
      'dnsbl.sorbs.net'	,'drone.abuse.ch'	,'duinv.aupads.org',
      'dul.dnsbl.sorbs.net',	'http.dnsbl.sorbs.net',
      'ips.backscatterer.org'	,'ix.dnsbl.manitu.net'	,'korea.services.net',
      'misc.dnsbl.sorbs.net',		'orvedb.aupads.org'
       ,	'proxy.bl.gweep.ca'	,'psbl.surriel.com',
      'relays.bl.gweep.ca',	'relays.nether.net',	
      'singular.ttk.pte.hu'	,'smtp.dnsbl.sorbs.net'	,'socks.dnsbl.sorbs.net',
      'spam.abuse.ch'	,'spam.dnsbl.anonmails.de'	,'spam.dnsbl.sorbs.net',
        'spambot.bls.digibase.ca',	'spamrbl.imp.ch',
      'spamsources.fabel.dk'	,'ubl.lashback.com',	'ubl.unsubscore.com',
      'virus.rbl.jp',	'web.dnsbl.sorbs.net',	'wormrbl.imp.ch'
        ,'z.mailspike.net'	,
      'zombie.dnsbl.sorbs.net'		];

    const blacklistResults = await Promise.all(
      domains.map(async (domain) => {
        try {
          const result = await checkDomainBlacklist(domain, blacklist, 6000);
          return { domain, blacklistResult: result };
        } catch (error) {
          // Handle the error for this specific domain
          console.error(`Error checking blacklist for ${domain}: ${error.message}`);
          return { domain, blacklistResult: { status: 'error', message: error.message } };
        }
      })
    );

    

    res.json({ domainBlacklistPairs: blacklistResults });
  } catch (error) {
    console.error('Error checking domain blacklist:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/blocklist', async (req, res) => {
  const { domains } = req.body;

  try {
    
const blocklist=['pbl.spamhaus.org','sbl.spamhaus.org','xbl.spamhaus.org'
,'zen.spamhaus.org','b.barracudacentral.org','bl.spamcop.net'
]

    const blocklistResults = await Promise.all(
      domains.map(async (domain) => {
        try {
          const result = await checkDomainBlacklist(domain, blocklist, 6000);
          return { domain, blocklistResult: result };
        } catch (error) {
          // Handle the error for this specific domain
          console.error(`Error checking blocklist for ${domain}: ${error.message}`);
          return { domain, blocklistResult: { status: 'error', message: error.message } };
        }
      })
    );

    

    res.json({ domainBlacklistPairs: blocklistResults });
  } catch (error) {
    console.error('Error checking domain blocklist:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Define the route for fetching A records
router.post('/arecords', async (req, res) => {
  const { domains } = req.body;

  if (!Array.isArray(domains) || domains.length === 0) {
    return res.status(400).json({ error: 'Domains array is required and should not be empty' });
  }

  try {
    const aRecordsResults = await Promise.all(
      domains.map(async (domain) => {
        try {
          const aRecords = await fetchARecords(domain);
          return { domain, aRecords };
        } catch (error) {
          // Handle the error for this specific domain
          console.error(`Error fetching A records for ${domain}: ${error.message}`);
          return { domain, error: error.message };
        }
      })
    );

    res.json({ aRecordsResults });
  } catch (error) {
    console.error('Error fetching A records:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Define the route for fetching AAAA records
router.post('/aaaRecords', async (req, res) => {
  const { domains } = req.body;

 

  try {
    const aaaaRecordsResults = await Promise.all(
      domains.map(async (domain) => {
        try {
          const aaaaRecords = await fetchAAAARecords(domain);
          return { domain, aaaaRecords };
        } catch (error) {
          // Handle the error for this specific domain
          console.error(`Error fetching AAAA records for ${domain}: ${error.message}`);
          return { domain, error: error.message };
        }
      })
    );

    res.json({ aaaaRecordsResults });
  } catch (error) {
    console.error('Error fetching AAAA records:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Define the route for fetching BIMI records
router.post('/bimiRecords', async (req, res) => {
  const { domains } = req.body;

  if (!Array.isArray(domains) || domains.length === 0) {
    return res.status(400).json({ error: 'Domains array is required and should not be empty' });
  }

  try {
    const bimiRecordsResults = await Promise.all(
      domains.map(async (domain) => {
        try {
          const bimiRecords = await fetchBimiRecord(domain);
          return { domain, bimiRecords };
        } catch (error) {
          // Handle the error for this specific domain
          console.error(`Error fetching BIMI records for ${domain}: ${error.message}`);
          return { domain, error: error.message };
        }
      })
    );

    res.json({ bimiRecordsResults });
  } catch (error) {
    console.error('Error fetching BIMI records:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Define the route for performing the checkDomainForwarding operation for an array of domains
router.post('/checkdomainforwarding', async (req, res) => {
  const { domains } = req.body;

  if (!Array.isArray(domains) || domains.length === 0) {
    return res.status(400).json({ error: 'Domains array is required and should not be empty' });
  }

  try {
    const results = await Promise.all(domains.map(checkDomainForwarding));
    const domainForwardingPairs = domains.map((domain, index) => ({
      domain,
      forwardingInfo: results[index],
    }));

    res.json({ domainForwardingPairs });
  } catch (error) {
    console.error('Error performing checkdomainforwarding:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/dkimRecords', async (req, res) => {
  const { domains } = req.body;
  try {
    const dkimRecordsPromises = domains.map(async (domain) => {
      const dkimRecords = await fetchAllDkimRecords(domain, "google");
      return { domain, dkimRecords }; // Include the domain name in the response
    });
    const dkimRecordsArray = await Promise.all(dkimRecordsPromises);

    res.json({ dkimRecords: dkimRecordsArray });
  } catch (error) {
    console.error('Error fetching DKIM records:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/tlsrptRecords', async (req, res) => {
  const { domains } = req.body;
  try {
    const tlsRptRecordsPromises = domains.map((domain) => fetchTlsRptRecord(domain));
    const tlsRptRecordsArray = await Promise.all(tlsRptRecordsPromises);

    const domainTlsRptPairs = domains.map((domain, index) => ({
      domain,
      tlsRptRecords: tlsRptRecordsArray[index],
    }));

    res.json({ domainTlsRptPairs });
  } catch (error) {
    console.error('Error fetching TLS-RPT records:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Define a POST route to capture screenshots for multiple domains and upload them to Google Drive
router.post('/captureSS', async (req, res) => {
  try {
    const { domains, sharedEmails } = req.body;

    // Array to store the results
    const results = [];

    // Iterate through the array of domains
    for (const domain of domains) {
      const url = `https://${domain}`; // Assuming all domains use HTTPS

      // Capture the screenshot and upload it to Google Drive
      const imageUrl = await captureScreenshotAndUpload(url, sharedEmails);

      // Add the result to the array
      results.push({ domain, imageUrl });
    }

    // Respond with the array of results
    res.status(200).json({ results });
  } catch (error) {
    console.error('Route error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


router.post('/mtaSts', async (req, res) => {
  const { domains } = req.body;
  try {
    const mtaStsResults = await Promise.all(
      domains.map((domain) => fetchMtaSts(domain))
    );

    // Combine the domains and their MTA-STS results into an array of objects
    const domainMtaStsPairs = domains.map((domain, index) => ({
      domain,
      mtaStsRecords: mtaStsResults[index],
    }));

    res.json({ domainMtaStsPairs });
  } catch (error) {
    console.error('Error fetching MTA-STS records:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const getDaysBetween = (validFrom, validTo) => {
  return Math.round(Math.abs(+validFrom - +validTo) / 8.64e7);
};

const getDaysRemaining = (validFrom, validTo) => {
  const daysRemaining = getDaysBetween(validFrom, validTo);
  if (new Date(validTo).getTime() < new Date().getTime()) {
      return -daysRemaining;
  }
  return daysRemaining;
};

//SSL certificate checks
async function getSSLCertificateInfo(host, timeoutMilliseconds) {
  try {
    if (!validator.isFQDN(host)) {
      throw new Error('Invalid host.');
    }
    const options = {
      agent: false,
      method: 'HEAD',
      port: 443,
      rejectUnauthorized: false,
      hostname: host,
    };

    const res = await Promise.race([
      new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
          resolve(res);
        });
        req.on('error', reject);
        req.end();
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('SSL certificate retrieval timed out')), timeoutMilliseconds)
      ),
    ]);

    const crt = res.connection.getPeerCertificate();
    const vFrom = crt.valid_from;
    const vTo = crt.valid_to;
    const validTo = new Date(vTo);
    console.log(`SSL processed for ${host}`);
    return {
      daysRemaining: getDaysRemaining(new Date(), validTo),
      valid: res.socket.authorized || false,
      validFrom: new Date(vFrom).toISOString(),
      validTo: validTo.toISOString(),
    };
  } catch (e) {
    throw e;
  }
}

router.post('/ssl', async (req, res) => {
  const { domains } = req.body;

  try {
    let domainSSLRecords = await Promise.all(
      domains.map(async (domain) => {
        try {
          const sslInfo = await getSSLCertificateInfo(domain,5000);
          return {
            domain,
            domainSSLResults: sslInfo,
          };
        } catch (error) {
          return {
            domain,
            error: `Error encountered: ${error.message}`,
          };
        }
      })
    );

    res.send(domainSSLRecords);
  } catch (err) {
    res.status(500).json({
      error: `Error encountered: ${err.message}`,
    });
  }
});

module.exports = router;
