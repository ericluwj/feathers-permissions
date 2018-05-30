const { Forbidden } = require('@feathersjs/errors');
const debug = require('debug')('feathers-permissions');

module.exports = function checkPermissions (options = {}) {
  options = Object.assign({
    entity: 'user',
    field: 'permissions'
  }, options);

  const { entity: entityName, field, roles } = options;

  if (!Array.isArray(roles)) {
    throw new Error(`'roles' option for feathers-permissions hook must be an array`);
  }

  return function (req, res, next) {
    debug('Running checkPermissions hook with options:', options);

    const entity = req[entityName];

    if (!entity) {
      debug(`req.${entityName} does not exist. If you were expecting it to be defined check your middleware order and your idField options in your auth config.`);
      return Promise.reject(new Forbidden('You do not have the correct permissions (invalid permission entity).'));
    }

    let permissions = entity[field] || [];

    // Normalize permissions. They can either be a
    // comma separated string or an array.
    if (typeof permissions === 'string') {
      permissions = permissions.split(',').map(current => current.trim());
    }

    const requiredPermissions = [
      '*'
    ];

    roles.forEach(role => {
      requiredPermissions.push(
        `${role}`,
        `${role}:*`
      );
    });

    debug(`Required Permissions`, requiredPermissions);

    const permitted = permissions.some(permission => requiredPermissions.includes(permission));

    req.permitted = req.permitted || permitted;

    if (options.error !== false && !req.permitted) {
      return Promise.reject(new Forbidden('You do not have the correct permissions.'));
    }

    return Promise.resolve(context);
  };
};
