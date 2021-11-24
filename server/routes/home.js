const express = require('express');
const router = express.Router();
const verify = require('../middleware/verifyToken');

router.get('/', verify, (req,res)=>{
  console.log('!!verify cleared!!')
  res.json({
    posts:{
      title:'verifyed cleared',
      description:'random data you shouldnt access'
    }
  });
});

module.exports = router;