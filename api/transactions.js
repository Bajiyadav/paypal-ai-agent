const transactHandler = require('./transact');

module.exports = (req, res) => {
  return transactHandler(req, res);
};
