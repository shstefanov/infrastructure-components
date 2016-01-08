var assert = require("assert");
var test = require("infrastructure/test_env");

var structure = "models";
var target    = "Users";

var address = function(method){ return [structure, target, method].join("."); };
describe(`Register user model\n  [${__filename}]`, function(){
  var env;
  it("Starts application", function(next){
    test.start({ only: [structure], process_mode: "cluster", options: { drop: true } }, function(err, _env){
      assert.equal(err, null);
      env = _env;
      next();
    });
  });

  it("Registers user", function(next){
    env.i.do(address("register"), {
      username: "testuser",
      email: "testuser@test.com",
      avatar: "http://some.url.to/image",
      password: "123456-aaaa"

    }, function(err, token){
      assert.equal(err, null);
      assert.equal(/^[0-9a-f]{128}$/.test(token), true);
      next();
    });
  });

  var user;
  it("User exists", function(next){
    env.i.do(address("findOne"), {username: "testuser"}, function(err, _user){
      assert.equal(err, null);
      user = _user;
      next();
    })
  });

  it("Can not login without verification", function(next){
    env.i.do(address("login"), {username: user.username, password: "123456-aaaa"}, function(err, user){
      assert.equal(user, null);
      assert.equal(err, "Wrong username or password");
      next();
    });
  });

  var verify_token;
  it("Get token", function(next){
    env.i.do(address("findOne"), {username: user.username}, function(err, user){
      assert.equal(err, null);
      assert.equal(/^[0-9a-f]{128}$/.test(user.verify_token), true);
      verify_token = user.verify_token;
      next();
    });
  });

  // User should confirm it's registration by email
  it("Verifying user registration", function(next){
    env.i.do(address("verify"), verify_token, function(err, user){
      assert.equal(err, null);
      next();
    })
  });

  it("Login user", function(next){
    env.i.do(address("login"), {username: user.username, password: "123456-aaaa"}, function(err, user){
      assert.equal(err, null);
      assert.deepEqual(user, { username: 'testuser', avatar: 'http://some.url.to/image' });
      next();
    });
  });

  var new_password
  it("Forgots password", function(next){
    env.i.do(address("forgot"), "testuser@test.com", function(err, new_pass){
      assert.equal(err, null);
      new_password = new_pass;
      next();
    });
  });

  it("Can not login with old password", function(next){
    env.i.do(address("login"), {username: user.username, password: "123456-aaaa"}, function(err, user){
      assert.equal(user, null);
      assert.equal(err, "Wrong username or password");
      next();
    });
  });

  it("Can login with new password", function(next){
    env.i.do(address("login"), {username: user.username, password: new_password}, function(err, user){
      assert.equal(err, null);
      assert.deepEqual(user, { username: 'testuser', avatar: 'http://some.url.to/image' });
      next();
    });
  });

  it("Stops application", function(next){
    env.stop(function(err){
      assert.equal(err, null);
      next();
    });
  });


});