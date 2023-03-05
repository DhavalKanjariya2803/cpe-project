const fs = require('fs');
const JSZip = require('jszip');
const zip = new JSZip();
const unzipper = require('unzipper');



async function loadJsonData() {
    try {
      const dataDir = './data';
      const zipFiles = fs.readdirSync(dataDir).filter((file) => {
        return file.endsWith('.zip');
      });
      let jsonData = [];
  
      await Promise.all(zipFiles.map(async (zipFile) => {
        const fileStream = fs.createReadStream(`${dataDir}/${zipFile}`);
        const unzipStream = unzipper.Parse();
  
        await fileStream.pipe(unzipStream).on('entry', async (entry) => {
          if (entry.path.endsWith('.json')) {
            const json = await entry.buffer();
            jsonData = jsonData.concat(JSON.parse(json));
          } else {
            entry.autodrain();
          }
        }).promise();
      }));
      return jsonData;
    } catch (error) {
      console.log(error);
    }
  }

module.exports = {
    async searchData(req, res) {  
        try {
            const jsonData = await loadJsonData();
            const inputArray = req.body;
            // const inputArray = [
            //     "cpe:2.3:o:intel:ethernet_controller_e810_firmware:*:*:*:*:*:*:*:*",
            //     "cpe:2.3:a:intel:graphics_drivers:*:*:*:*:*:*:*:*"
            //   ]
            const matchingRecords = [];
            let matchedData = []
            inputArray.forEach((cpeString) => {
                const vendor = cpeString.split(':')[3];
                const product = cpeString.split(':')[4];
                const version = cpeString.split(':')[5] || '';
                console.log(vendor, product, version)
                jsonData.forEach((ele)=> {
                  const matchingData = ele.CVE_Items.filter((record) => {
                    const configurations = record.configurations;
                    if (configurations) {
                      const nodes = configurations.nodes;
                      if (nodes) {
                        const matchingNode = nodes.find((node) => {
                          if (node.operator === 'OR') {
                            return node.children.some((child) => {
                              return (
                                child.cpe_match &&
                                child.cpe_match[0].cpe23Uri.includes(vendor) &&
                                child.cpe_match[0].cpe23Uri.includes(product) &&
                                child.cpe_match[0].cpe23Uri.includes(version)
                              );
                            });
                          } else if (node.operator === 'AND') {
                            return node.children.every((child) => {
                              return (
                                child.cpe_match &&
                                child.cpe_match[0].cpe23Uri.includes(vendor) &&
                                child.cpe_match[0].cpe23Uri.includes(product) &&
                                child.cpe_match[0].cpe23Uri.includes(version)
                              );
                            });
                          } else {
                            return false;
                          }
                        });
              
                        if (matchingNode) {
                          return true;
                        }
                      }
                    }
                    return false;
                  });
                  if(matchingData.length) {
                    matchedData = [...new Set([...matchedData, ...matchingData])]
                  }
                  const matchingIds = matchingData.map((record) => {
                    return record.cve.CVE_data_meta.ID;
                  });
              
                  if (matchingIds.length > 10) {
                    matchingRecords.push(matchingIds.slice(0, 10));
                  } else {
                    matchingRecords.push(matchingIds);
                  }

                })
            
            });
            res.json(matchedData);
        } catch (error) {
            console.log(error)
        }
    },
  };
