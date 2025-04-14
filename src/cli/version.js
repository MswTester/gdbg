/**
 * 버전 정보 관리 모듈
 */

const fs = require('fs');
const path = require('path');

// package.json에서 버전 정보 가져오기
function getVersion() {
  try {
    const packagePath = path.join(__dirname, '../../package.json');
    const packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    return packageData.version;
  } catch (error) {
    console.error('버전 정보를 읽는 중 오류 발생:', error.message);
    return '0.0.0'; // 기본 버전
  }
}

module.exports = {
  getVersion
}; 