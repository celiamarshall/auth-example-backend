const db = require('../../db')
const bcrypt = require('bcrypt')
const userModel = require('./users')

//////////////////////////////////////////////////////////////////////////////
// Basic CRUD Methods
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
// Login
//
// 1. Check to see if user already exists
//   a. if not, return a 400 with appropriate error message
// 2. compare password in the database with the password provided by user
// 3. If the passwords do not match, respond with 401 Unauthorized
// 4. strip hashed password away from object
// 5. "return/continue" promise
//////////////////////////////////////////////////////////////////////////////

function login(username, password){
  let user 
  return userModel.getOneByUserName(username)
  .then( (data) => {
    if (!data) throw {status: 400, message: 'Error'}

    user = data

    return bcrypt.compare(password, data.password)
  })
  .then( (status) => {
    if (!status) throw {status: 401, message: 'Unauthorized'}

    delete user.password
    
    return user
  })
}

module.exports = {
  login
}
