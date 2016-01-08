var crypto  = require('crypto');
var bcrypt  = require('bcrypt');
var _       = require("underscore");
var helpers = require("infrastructure/lib/helpers");

function genSalt(ctx, cb){
  bcrypt.genSalt(10, function(err, salt) { if(err) return cb(err);
    ctx.salt = salt; cb(null, ctx);
  });
}

function genHash(ctx, cb){
  bcrypt.hash(ctx.password, ctx.salt, function(err, hash) {           if(err) return cb(err);
    ctx.hash = hash;
    cb(null, ctx);
  });
}

module.exports = require("infrastructure-mongodb/MongoLayer").extend("UsersLayer", {

  collectionName: "Users",
  publicFields:   ["username", "avatar"],

  callable: ["login", "register", "find", "findOne", "update", "verify", "forgot"],

  login: helpers.chain([

    function(credentials, options, cb){
      cb(null, {
        password: credentials.password,
        query:    _.extend(_.pick(credentials, this.publicFields ), {verified: true}),
      });
    },

    function(ctx, cb){
      this.findOne( ctx.query, {}, function(err, user){ if(err) return cb(err);
        ctx.user = user;
        cb(null, ctx);
      });
    },
    function(ctx, cb){
      if(!ctx.user) return cb("Wrong username or password");
      bcrypt.compare(ctx.password, ctx.user.password, function(err, res) { if(err) return cb(err);
        if(!res) return cb("Wrong username or password");
        cb(null, ctx);
      });
    },

    function(ctx, cb){
      cb(null, _.pick(ctx.user, this.publicFields));
    }
  ]),
  
  register: helpers.chain([
    
    function(data, options, cb){
      cb(null, {
        password:       data.password,
        user_data:      _.clone( data ),
        config:         this.env.config
      });
    },

    genSalt, genHash,

    function(ctx, cb){
      ctx.db_data = _.extend({}, ctx.user_data, { password: ctx.hash, verified: false });
      cb(null, ctx);
    },

    function(ctx, cb){
      var self = this;
      function createToken(){
        var token = crypto.randomBytes(64).toString('hex');
        self.findOne({verify_token: token}, {}, function(err, user){       if(err) return cb(err);
          if(user) return createToken();
          ctx.db_data.verify_token = token;
          cb(null, ctx);
        });
      }
      createToken();
    },

    function(ctx, cb){
      var fields = this.publicFields;
      this.create(ctx.db_data, {}, function(err, doc){                    if(err) return cb(err);
        cb(null, ctx.db_data.verify_token);
      });
    }
  ]),

  verify: helpers.chain([
    function(token, options, cb){
      if(!/^[0-9a-f]{128}$/.test(token)) return cb("Invalid token");
      cb(null, { token: token });
    },

    function(ctx, cb){
      this.findOne({verify_token: ctx.token}, {fields: ["_id"]}, function(err, user){     if(err) return cb(err);
        if(!user) return cb("Invalid token");
        ctx.user = user;
        cb(null, ctx);
      });
    },

    function(ctx, cb){
      this.update({_id: ctx.user._id}, {$unset:{verify_token:1}, $set:{verified: true}}, function(err){     if(err) return cb(err);
        cb(null, true);
      });
    }
  ]),

  // Retusrns generated password
  forgot: helpers.chain([
    function(email, options, cb){
      if(typeof email !== "string") return cb("Invalid email");
      cb(null, {email: email});
    },
    function(ctx, cb){
      this.findOne({email: ctx.email}, {}, function(err, user){ if(err) return cb(err);
        if(!user) return cb("Can't find user");
        ctx.user = user;
        cb(null, ctx);
      });
    },


    genSalt, function(ctx, cb){ ctx.password = ctx.salt; cb(null, ctx); },

    genSalt, genHash, function(ctx, cb){
      this.update({_id: ctx.user._id}, {$set:{password:ctx.hash}}, function(err){   if(err) return cb(err);
        cb(null, ctx.password);
      });
    }
  ])


});