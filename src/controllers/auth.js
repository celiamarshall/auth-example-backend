const authModel = require('../models/auth')
const jwt = require('jsonwebtoken')

//////////////////////////////////////////////////////////////////////////////
// Basic CRUD Methods
//////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////
// Login Controller
//
// 1. Make sure that request is good
// 2. Attempt Login
// 3. Create token
// 4. Send back token
//////////////////////////////////////////////////////////////////////////////

function login(req, res, next){
  if (!req.body.username) {
    return next({status: 400, message: 'Bad request'})
  } 

  if (!req.body.password) {
    return next({status: 400, message: 'Bad request'})
  }

  authModel.login(req.body.username, req.body.password)
  .then ((user) => {
    const token = jwt.sign({user: user.id}, process.env.SECRET)

    res.status(201).send( {token} )
  })
  .catch(next)
}

//////////////////////////////////////////////////////////////////////////////
// Quality of Life functions
//////////////////////////////////////////////////////////////////////////////

function isAuthenticated(req, res, next){
  if(!req.header.authorization){
    return next({ status: 401, message: 'Unauthorized' })
  }
  
  const [scheme, credentials] = req.headers.authorization.split(' ')

  jwt.verify(credentials, process.env.SECRET, (err, payload)=>{
    if(err){
      return next({ status: 401, message: 'Unauthorized' })
    }

    req.claim = payload

    next()
  })
}

function isSelf(req, res, next){

  if(parseInt(req.params.userId) !== req.claim.id){
    return next({ status: 401, message: 'Unauthorized' })
  }

  next()
}



module.exports = {
  login,
  isAuthenticated,
  isSelf
}
