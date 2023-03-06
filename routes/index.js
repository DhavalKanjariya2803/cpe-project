var express = require('express');
var router = express.Router();
const contactsController  = require('../controllers').contacts;
const cpeController = require('../controllers/cpeController');


/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/api/search',  cpeController.searchData)

module.exports = router;
