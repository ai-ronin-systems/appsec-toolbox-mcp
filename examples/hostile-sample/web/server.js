const express = require('express');
const app = express();
app.get('/', function (req, res) { eval(req.query.x); res.send('<h1>' + req.query.name + '</h1>'); });
