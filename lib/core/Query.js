"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("../core");
var enums_1 = require("../enums");
var utils_1 = require("../utils");
/**
 *  Represents the inner `Query` class that helps build an access information
 *  for querying and checking permissions, from the underlying grants model.
 *  You can get a first instance of this class by calling
 *  `AccessControl#can(<subject>)` method.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
var Query = /** @class */ (function () {
    /**
     *  Initializes a new instance of `Query`.
     *  @private
     *
     *  @param {Any} grants
     *         Underlying grants model against which the permissions will be
     *         queried and checked.
     *  @param {string|Array<String>|IQueryInfo} [subjectOrInfo]
     *         Either a single or array of subjects or an
     *         {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` arbitrary object}.
     */
    function Query(grants, subjectOrInfo) {
        /**
         *  Inner `IQueryInfo` object.
         *  @protected
         *  @type {IQueryInfo}
         */
        this._ = {};
        this._grants = grants;
        if (typeof subjectOrInfo === 'string' || Array.isArray(subjectOrInfo)) {
            // if this is just subject(s); a string or array; we start building
            // the grant object for this.
            this.subject(subjectOrInfo);
        }
        else if (utils_1.utils.type(subjectOrInfo) === 'object') {
            // if this is a (permission) object, we directly build attributes
            // from grants.
            if (Object.keys(subjectOrInfo).length === 0) {
                throw new core_1.AccessControlError('Invalid IQueryInfo: {}');
            }
            this._ = subjectOrInfo;
        }
        else if (subjectOrInfo !== undefined) {
            // undefined is allowed (`subject` can be omitted) but throw if some
            // other type is passed.
            throw new core_1.AccessControlError('Invalid subject(s), expected a valid string, string[] or IQueryInfo.');
        }
    }
    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------
    /**
     *  A chainer method that sets the subject(s) for this `Query` instance.
     *  @param {String|Array<String>} subjects
     *         A single or array of subjects.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    Query.prototype.subject = function (subject) {
        this._.subject = subject;
        return this;
    };
    /**
     *  A chainer method that sets the resource for this `Query` instance.
     *  @param {String} resource
     *         Target resource for this `Query` instance.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    Query.prototype.resource = function (resource) {
        this._.resource = resource;
        return this;
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  subject(s) can "create" their "own" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.createOwn = function (resource) {
        return this._getPermission(enums_1.Action.CREATE, enums_1.Possession.OWN, resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  subject(s) can "create" "any" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.createAny = function (resource) {
        return this._getPermission(enums_1.Action.CREATE, enums_1.Possession.ANY, resource);
    };
    /**
     *  Alias if `createAny`
     *  @private
     */
    Query.prototype.create = function (resource) {
        return this.createAny(resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  subject(s) can "read" their "own" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.readOwn = function (resource) {
        return this._getPermission(enums_1.Action.READ, enums_1.Possession.OWN, resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  subject(s) can "read" "any" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.readAny = function (resource) {
        return this._getPermission(enums_1.Action.READ, enums_1.Possession.ANY, resource);
    };
    /**
     *  Alias if `readAny`
     *  @private
     */
    Query.prototype.read = function (resource) {
        return this.readAny(resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  subject(s) can "update" their "own" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.updateOwn = function (resource) {
        return this._getPermission(enums_1.Action.UPDATE, enums_1.Possession.OWN, resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  subject(s) can "update" "any" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.updateAny = function (resource) {
        return this._getPermission(enums_1.Action.UPDATE, enums_1.Possession.ANY, resource);
    };
    /**
     *  Alias if `updateAny`
     *  @private
     */
    Query.prototype.update = function (resource) {
        return this.updateAny(resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  subject(s) can "delete" their "own" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.deleteOwn = function (resource) {
        return this._getPermission(enums_1.Action.DELETE, enums_1.Possession.OWN, resource);
    };
    /**
     *  Queries the underlying grant model and checks whether the current
     *  subject(s) can "delete" "any" resource.
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    Query.prototype.deleteAny = function (resource) {
        return this._getPermission(enums_1.Action.DELETE, enums_1.Possession.ANY, resource);
    };
    /**
     *  Alias if `deleteAny`
     *  @private
     */
    Query.prototype.delete = function (resource) {
        return this.deleteAny(resource);
    };
    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------
    /**
     *  @private
     *  @param {String} action
     *  @param {String} possession
     *  @param {String} [resource]
     *  @returns {Permission}
     */
    Query.prototype._getPermission = function (action, possession, resource) {
        this._.action = action;
        this._.possession = possession;
        if (resource)
            this._.resource = resource;
        return new core_1.Permission(this._grants, this._);
    };
    return Query;
}());
exports.Query = Query;
