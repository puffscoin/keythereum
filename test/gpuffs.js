/* eslint-env node, mocha */

"use strict";

var fs = require("fs");
var join = require("path").join;
var crypto = require("crypto");
var assert = require("chai").assert;
var gpuffs = require("gpuffs");
var puffkeys = require("../");
var checkKeyObj = require("./checkKeyObj");

var NUM_TESTS = 1000;
var TIMEOUT = 10000;
var DATADIR = join(__dirname, "fixtures");

var options = {
  persist: false,
  flags: {
    networkid: "10101",
    port: 30304,
    rpcport: 8547,
    nodiscover: null,
    datadir: DATADIR,
    ipcpath: join(DATADIR, "gpuffs.ipc"),
    password: join(DATADIR, ".password")
  }
};

var pbkdf2 = puffkeys.crypto.pbkdf2;
var pbkdf2Sync = puffkeys.crypto.pbkdf2Sync;

// gpuffs.debug = true;

function createPuffscoinKey(passphrase) {
  var dk = puffkeys.create();
  var key = puffkeys.dump(passphrase, dk.privateKey, dk.salt, dk.iv);
  return JSON.stringify(key);
}

puffkeys.constants.quiet = true;

describe("Unlock randomly-generated accounts in geth", function () {
  var password, hashRounds, i;

  var test = function (t) {

    var label = "[" + t.kdf + " | " + t.hashRounds + " rounds] generate key file using password '" + t.password +"'";

    it(label, function (done) {
      var json, keyObject;
      this.timeout(TIMEOUT*2);

      if (t.sjcl) {
        puffkeys.crypto.pbkdf2 = undefined;
        puffkeys.crypto.pbkdf2Sync = undefined;
      } else {
        puffkeys.crypto.pbkdf2 = pbkdf2;
        puffkeys.crypto.pbkdf2Sync = pbkdf2Sync;
      }

      json = createPuffscoinKey(t.password);
      assert.isNotNull(json);

      keyObject = JSON.parse(json);
      assert.isObject(keyObject);
      checkKeyObj.structure(puffkeys, keyObject);

      puffkeys.exportToFile(keyObject, join(DATADIR, "keystore"), function (keypath) {
        fs.writeFile(options.flags.password, t.password, function (ex) {
          var fail;
          if (ex) return done(ex);
          options.flags.unlock = keyObject.address;
          options.flags.etherbase = keyObject.address;
          gpuffs.start(options, {
            stderr: function (data) {
              if (gpuffs.debug) process.stdout.write(data);
              if (data.toString().indexOf("16MB") > -1) {
                gpuffs.trigger(null, gpuffs.proc);
              }
            },
            close: function () {
              fs.unlink(options.flags.password, function (exc) {
                if (exc) return done(exc);
                fs.unlink(keypath, function (exc) {
                  if (exc) return done(exc);
                  done(fail);
                });
              });
            }
          }, function (err, spawned) {
            if (err) return done(err);
            if (!spawned) return done(new Error("where's the geth?"));
            gpuffs.stdout("data", function (data) {
              var unlocked = "Account '" + keyObject.address+
                "' (" + keyObject.address + ") unlocked.";
              if (data.toString().indexOf(unlocked) > -1) {
                gpuffs.stop();
              }
            });
            gpuffs.stderr("data", function (data) {
              if (data.toString().indexOf("Fatal") > -1) {
                fail = new Error(data);
                gpuffs.stop();
              }
            });
          });
        });
      });
    });
  };

  for (i = 0; i < NUM_TESTS; ++i) {

    password = crypto.randomBytes(Math.ceil(Math.random()*100));
    hashRounds = Math.ceil(Math.random() * 300000);

    puffkeys.constants.pbkdf2.c = hashRounds;
    puffkeys.constants.scrypt.n = hashRounds;

    test({
      sjcl: false,
      password: password.toString("hex"),
      hashRounds: hashRounds,
      kdf: "pbkdf2"
    });
    test({
      sjcl: true,
      password: password.toString("hex"),
      hashRounds: hashRounds,
      kdf: "pbkdf2"
    });
    test({
      password: password.toString("base64"),
      hashRounds: hashRounds,
      kdf: "scrypt"
    });

    test({
      sjcl: false,
      password: password.toString("hex"),
      hashRounds: hashRounds,
      kdf: "pbkdf2"
    });
    test({
      sjcl: true,
      password: password.toString("hex"),
      hashRounds: hashRounds,
      kdf: "pbkdf2"
    });
    test({
      password: password.toString("base64"),
      hashRounds: hashRounds,
      kdf: "scrypt"
    });
  }

});
