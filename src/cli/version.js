/**
 * Version info manage module
 */

const fs = require('fs');
const path = require('path');

// Fetch version information from package.json
function getVersion() {
  try {
    const packagePath = path.join(__dirname, '../../package.json');
    const packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    return packageData.version;
  } catch (error) {
    console.error('Error occured reading version:', error.message);
    return '0.0.0'; // Default version
  }
}

module.exports = {
  getVersion
}; 