const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: {type: String, required: true},
  email: {type: String, required: true},
  password: {type: String},
  role: {type: String, default: "user", enum:["user","admin"]},
  date: {type: Date, default:Date.now},
  address:{type: String},
  linkedin:{type: String},
  phonenum:{type: String}
});
const User = mongoose.model('User',UserSchema);

module.exports = User;