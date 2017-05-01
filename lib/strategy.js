// Load modules.
var passport = require('passport-strategy')
  , flowstate = require('flowstate');
  , util = require('util');

function _configureStore(options) {

  if (!options.flowstate) { return; }

  var config = {};

  ['store', 'get', 'clean', 'name'].forEach((k) => {
    if (options[k]) { config[k] = options[k]; }
  });

  // run in strict mode (must have expected name)
  if (options['strict'] && config['name']) {
    config['strict'] = options['strict'];
  }

  this.flowstate = Object.assign(this.flowstate || {}, config);

}

function StateStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  passport.Strategy.call(this);
  this.name = 'state';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;

  _.configureStore.call(this, options);
}

// Inherit from `passport.Strategy`.
util.inherits(StateStrategy, passport.Strategy);


StateStrategy.prototype.authenticate = function(req, options) {
  options = options || {};

  // allow overwrite of store configuration
  _.configureStore.call(this, options);

  var self = this;

  function verification (state) {

    function verified(err, user, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(info); }

      self.success(user, info);
    }

    try {
      var arity = self.verify.length;
      if (self.passReqToCallback) {
        if (arity == 4) {
          self.verify(req, state.user, state, verified);
        } else { // arity == 3
          self.verify(req, state.user, verified);
        }
      } else {
        if (arity == 3) {
          self.verify(state.user, state, verified);
        } else { // arity == 2
          self.verify(state.user, verified);
        }
      }
    } catch (ex) {
      return self.error(ex);
    }

  }

  // ----- HANDLE DIRECT CASE -----

  if (!this.flowstate) {
    return (!!req.state)
      ? verification(req.state)
      : this.fail();
  }

  // ----- HANDLE FLOWSTATE CASE -----

  if (!this.flowstate.store) { return this.error(); } // only required argument

  // FILO
  var stack = [];

  var loadOpts = {};
  if (this.flowstate.name)  { loadOpts['name']      = this.flowstate.name; }
  if (this.flowstate.get)   { loadOpts['getHandle'] = this.flowstate.get;  }

  var lm = (loadOpts.length)
      ? flowstate.middleware.load(this.flowstate.store, loadOpts)
      : flowstate.middleware.load(this.flowstate.store);

  stack.append(lm);

  if (!!this.flowstate.clean) {
    var cm = flowstate.middleware.clean(this.flowstate.store, this.flowstate.clean);
    stack.append(cm);
  }

  function exec(err) {
    if (err) { return self.error(err); }

    var next = stack.pop();
    if (!next) {
      var state = (self.flowstate.strict)
          ? (req.state)
          : (req.state || req._state);

      if (!state) { return self.fail(); }
      return verification(state);
    }

    var res = () => { return self.error(); } // if res is called for any reason, error out
    next(req, res, exec);
  }

  exec();
};


// Expose constructor.
module.exports = StateStrategy;
