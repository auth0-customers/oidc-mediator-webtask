var dotenv = require('dotenv');
var app = require('./server');

dotenv.config();

// Create Server
var server = app.listen(8081, function () {

  var host = server.address().address;
  var port = server.address().port;

  console.log("Mediator listening at http://%s:%s", host, port)
});