var App = require("App");
module.exports = require("home.lib.View").extend({
  template: require("./Layout.ractive.html"),
  style: require("./Layout.less"),
  components: App.bulk( require.context("./sections", true, /\.\/[^/]+\/[^\/]+\.js$/), function(name, context, cb){ cb(name.split("/").shift()); }),
});