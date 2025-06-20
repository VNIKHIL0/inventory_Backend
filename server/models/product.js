const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: String,
  category: String,
  quantity: Number,
  price: Number
});

module.exports = mongoose.model('Product', productSchema);
