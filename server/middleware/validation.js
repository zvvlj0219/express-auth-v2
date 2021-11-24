const Joi = require('joi');

//register validation
const registerValidation = (data) => {

  const schema = Joi.object({
    email:Joi.string()
      .min(6).required().email(),
    username:Joi.string()
      .min(3).required(),
    password:Joi.string()
      .min(6).required()
  });
  return schema.validate(data)
}
  
//login validation
const loginValidation = (data) => {
  const schema = Joi.object({
    email:Joi.string()
      .min(6).required().email(),
    password:Joi.string()
      .min(6).required()
  });
  return schema.validate(data)
}

module.exports.registerValidation = registerValidation;
module.exports.loginValidation = loginValidation;