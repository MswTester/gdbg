/**
 * Utility Module
 */

/**
 * Get formatted time
 * @returns {string} Current time string
 */
function getTime() {
  return new Date().toTimeString().split(' ')[0];
}

/**
 * Format address value
 * @param {any} addr Address value
 * @returns {string} Formatted address string
 */
function formatAddress(addr) {
  if (!addr) return 'null';
  return addr.toString();
}

/**
 * Truncate string
 * @param {string} str Original string
 * @param {number} maxLength Maximum length
 * @returns {string} Truncated string
 */
function truncate(str, maxLength = 80) {
  if (!str) return '';
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength - 3) + '...';
}

/**
 * Format size
 * @param {number} size Size in bytes
 * @returns {string} Formatted size string
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