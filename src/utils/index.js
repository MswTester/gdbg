/**
 * 유틸리티 모듈
 */

/**
 * 시간 형식 가져오기
 * @returns {string} 현재 시간 문자열
 */
function getTime() {
  return new Date().toTimeString().split(' ')[0];
}

/**
 * 주소값 형식화
 * @param {any} addr 주소값
 * @returns {string} 형식화된 주소 문자열
 */
function formatAddress(addr) {
  if (!addr) return 'null';
  return addr.toString();
}

/**
 * 문자열 잘라내기
 * @param {string} str 원본 문자열
 * @param {number} maxLength 최대 길이
 * @returns {string} 잘라낸 문자열
 */
function truncate(str, maxLength = 80) {
  if (!str) return '';
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength - 3) + '...';
}

/**
 * 크기 형식화
 * @param {number} size 바이트 단위 크기
 * @returns {string} 형식화된 크기 문자열
 */
function formatSize(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(2)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(2)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

module.exports = {
  getTime,
  formatAddress,
  truncate,
  formatSize
}; 