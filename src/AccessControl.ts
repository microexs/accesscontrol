import { Access, IAccessInfo, Query, IQueryInfo, Permission, AccessControlError } from './core';
import { Action, Possession, actions, possessions } from './enums';
import { utils, ERR_LOCK } from './utils';

/**
 *  @classdesc
 *  AccessControl class that implements RBAC (Subject-Based Access Control) basics
 *  and ABAC (Attribute-Based Access Control) <i>resource</i> and <i>action</i>
 *  attributes.
 *
 *  Construct an `AccessControl` instance by either passing a grants object (or
 *  array fetched from database) or simply omit `grants` parameter if you are
 *  willing to build it programmatically.
 *
 *  <p><pre><code> const grants = {
 *      subject1: {
 *          resource1: {
 *              "create:any": [ attrs ],
 *              "read:own": [ attrs ]
 *          },
 *          resource2: {
 *              "create:any": [ attrs ],
 *              "update:own": [ attrs ]
 *          }
 *      },
 *      subject2: { ... }
 *  };
 *  const ac = new AccessControl(grants);</code></pre></p>
 *
 *  The `grants` object can also be an array, such as a flat list
 *  fetched from a database.
 *
 *  <p><pre><code> const flatList = [
 *      { subject: 'subject1', resource: 'resource1', action: 'create:any', attributes: [ attrs ] },
 *      { subject: 'subject1', resource: 'resource1', action: 'read:own', attributes: [ attrs ] },
 *      { subject: 'subject2', ... },
 *      ...
 *  ];</code></pre></p>
 *
 *  We turn this list into a hashtable for better performance. We aggregate
 *  the list by subjects first, resources second. If possession (in action
 *  value or as a separate property) is omitted, it will default to `"any"`.
 *  e.g. `"create"` ➞ `"create:any"`
 *
 *  Below are equivalent:
 *  <p><pre><code> const grants = { subject: 'subject1', resource: 'resource1', action: 'create:any', attributes: [ attrs ] }
 *  const same = { subject: 'subject1', resource: 'resource1', action: 'create', possession: 'any', attributes: [ attrs ] }</code></pre></p>
 *
 *  So we can also initialize with this flat list of grants:
 *  <p><pre><code> const ac = new AccessControl(flatList);
 *  console.log(ac.getGrants());</code></pre></p>
 *
 *  @author   Onur Yıldırım <onur@cutepilot.com>
 *  @license  MIT
 *
 *  @class
 *  @global
 *
 *  @example
 *  const ac = new AccessControl(grants);
 *
 *  ac.grant('admin').createAny('profile');
 *
 *  // or you can chain methods
 *  ac.grant('admin')
 *      .createAny('profile')
 *      .readAny('profile', ["*", "!password"])
 *      .readAny('video')
 *      .deleteAny('video');
 *
 *  // since these permissions have common resources, there is an alternative way:
 *  ac.grant('admin')
 *      .resource('profile').createAny().readAny(null, ["*", "!password"])
 *      .resource('video').readAny()..deleteAny();
 *
 *  ac.grant('user')
 *      .readOwn('profile', ["uid", "email", "address.*", "account.*", "!account.subjects"])
 *      .updateOwn('profile', ["uid", "email", "password", "address.*", "!account.subjects"])
 *      .deleteOwn('profile')
 *      .createOwn('video', ["*", "!geo.*"])
 *      .readAny('video')
 *      .updateOwn('video', ["*", "!geo.*"])
 *      .deleteOwn('video');
 *
 *  // now we can check for granted or denied permissions
 *  const permission = ac.can('admin').readAny('profile');
 *  permission.granted // true
 *  permission.attributes // ["*", "!password"]
 *  permission.filter(data) // { uid, email, address, account }
 *  // deny permission
 *  ac.deny('admin').createAny('profile');
 *  ac.can('admin').createAny('profile').granted; // false
 *
 *  // To add a grant but deny access via attributes
 *  ac.grant('admin').createAny('profile', []); // no attributes allowed
 *  ac.can('admin').createAny('profile').granted; // false
 *
 *  // To prevent any more changes:
 *  ac.lock();
 */
class AccessControl {

    /**
     *  @private
     */
    private _grants: any;

    /**
     *  @private
     */
    private _isLocked: boolean = false;

    /**
     *  Initializes a new instance of `AccessControl` with the given grants.
     *  @ignore
     *
     *  @param {Object|Array} [grants] - A list containing the access grant
     *      definitions. See the structure of this object in the examples.
     */
    constructor(grants?: any) {
        // explicit undefined is not allowed
        if (arguments.length === 0) grants = {};
        this.setGrants(grants);
    }

    // -------------------------------
    //  PUBLIC PROPERTIES
    // -------------------------------

    /**
     *  Specifies whether the underlying grants object is frozen and all
     *  functionality for modifying it is disabled.
     *  @name AccessControl#isLocked
     *  @type {Boolean}
     */
    get isLocked(): boolean {
        return this._isLocked && Object.isFrozen(this._grants);
    }

    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------

    /**
     *  Gets the internal grants object that stores all current grants.
     *
     *  @return {Object} - Hash-map of grants.
     *
     *  @example
     *  ac.grant('admin')
     *      .createAny(['profile', 'video'])
     *      .deleteAny(['profile', 'video'])
     *      .readAny(['video'])
     *      .readAny('profile', ['*', '!password'])
     *      .grant('user')
     *      .readAny(['profile', 'video'], ['*', '!id', '!password'])
     *      .createOwn(['profile', 'video'])
     *      .deleteOwn(['video']);
     *  // logging underlying grants model
     *  console.log(ac.getGrants());
     *  // outputs:
     *  {
     *    "admin": {
     *      "profile": {
     *        "create:any": ["*"],
     *        "delete:any": ["*"],
     *        "read:any": ["*", "!password"]
     *      },
     *      "video": {
     *        "create:any": ["*"],
     *        "delete:any": ["*"],
     *        "read:any": ["*"]
     *      }
     *    },
     *    "user": {
     *      "profile": {
     *        "read:any": ["*", "!id", "!password"],
     *        "create:own": ["*"]
     *      },
     *      "video": {
     *        "read:any": ["*", "!id", "!password"],
     *        "create:own": ["*"],
     *        "delete:own": ["*"]
     *      }
     *    }
     *  }
     */
    getGrants(): any {
        return this._grants;
    }

    /**
     *  Sets all access grants at once, from an object or array. Note that this
     *  will reset the object and remove all previous grants.
     *  @chainable
     *
     *  @param {Object|Array} grantsObject - A list containing the access grant
     *         definitions.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If called after `.lock()` is called or if
     *  passed grants object fails inspection.
     */
    setGrants(grantsObject: any): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        this._grants = utils.getInspectedGrants(grantsObject);
        return this;
    }

    /**
     *  Resets the internal grants object and removes all previous grants.
     *  @chainable
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     */
    reset(): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        this._grants = {};
        return this;
    }

    /**
     *  Freezes the underlying grants model and disables all functionality for
     *  modifying it. This is useful when you want to restrict any changes. Any
     *  attempts to modify (such as `#setGrants()`, `#reset()`, `#grant()`,
     *  `#deny()`, etc) will throw after grants are locked. Note that <b>there
     *  is no `unlock()` method</b>. It's like you lock the door and swallow the
     *  key. ;)
     *
     *  Remember that this does not prevent the `AccessControl` instance from
     *  being altered/replaced. Only the grants inner object is locked.
     *
     *  <b>A note about performance</b>: This uses recursive `Object.freeze()`.
     *  In NodeJS & V8, enumeration performance is not impacted because of this.
     *  In fact, it increases the performance because of V8 optimization.
     *  @chainable
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @example
     *  ac.grant('admin').create('product');
     *  ac.lock(); // called on the AccessControl instance.
     *  // or
     *  ac.grant('admin').create('product').lock(); // called on the chained Access instance.
     *
     *  // After this point, any attempt of modification will throw
     *  ac.setGrants({}); // throws
     *  ac.grant('user'); // throws..
     *  // underlying grants model is not changed
     */
    lock(): AccessControl {
        utils.lockAC(this);
        return this;
    }

    /**
     *  Extends the given subject(s) with privileges of one or more other subjects.
     *  @chainable
     *
     *  @param {string|Array<String>} subjects Subject(s) to be extended. Single subject
     *         as a `String` or multiple subjects as an `Array`. Note that if a
     *         subject does not exist, it will be automatically created.
     *
     *  @param {string|Array<String>} extenderRoles Subject(s) to inherit from.
     *         Single subject as a `String` or multiple subjects as an `Array`. Note
     *         that if a extender subject does not exist, it will throw.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If a subject is extended by itself or a
     *  non-existent subject. Or if called after `.lock()` is called.
     */
    extendRole(subjects: string | string[], extenderRoles: string | string[]): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        utils.extendRole(this._grants, subjects, extenderRoles);
        return this;
    }

    /**
     *  Removes all the given subject(s) and their granted permissions, at once.
     *  @chainable
     *
     *  @param {string|Array<String>} subjects - An array of subjects to be removed.
     *      Also accepts a string that can be used to remove a single subject.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     */
    removeRoles(subjects: string | string[]): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);

        let subjectsToRemove: string[] = utils.toStringArray(subjects);
        if (subjectsToRemove.length === 0 || !utils.isFilledStringArray(subjectsToRemove)) {
            throw new AccessControlError(`Invalid subject(s): ${JSON.stringify(subjects)}`);
        }
        subjectsToRemove.forEach((subjectName: string) => {
            if (!this._grants[subjectName]) {
                throw new AccessControlError(`Cannot remove a non-existing subject: "${subjectName}"`);
            }
            delete this._grants[subjectName];
        });
        // also remove these subjects from $extend list of each remaining subject.
        utils.eachRole(this._grants, (subjectItem: any, subjectName: string) => {
            if (Array.isArray(subjectItem.$extend)) {
                subjectItem.$extend = utils.subtractArray(subjectItem.$extend, subjectsToRemove);
            }
        });
        return this;
    }

    /**
     *  Removes all the given resources for all subjects, at once.
     *  Pass the `subjects` argument to remove access to resources for those
     *  subjects only.
     *  @chainable
     *
     *  @param {string|Array<String>} resources - A single or array of resources to
     *      be removed.
     *  @param {string|Array<String>} [subjects] - A single or array of subjects to
     *      be removed. If omitted, permissions for all subjects to all given
     *      resources will be removed.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     */
    removeResources(resources: string | string[], subjects?: string | string[]): AccessControl {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);

        // _removePermission has a third argument `actionPossession`. if
        // omitted (like below), removes the parent resource object.
        this._removePermission(resources, subjects);
        return this;
    }

    /**
     *  Gets all the unique subjects that have at least one access information.
     *
     *  @returns {Array<String>}
     *
     *  @example
     *  ac.grant('admin, user').createAny('video').grant('user').readOwn('profile');
     *  console.log(ac.getRoles()); // ["admin", "user"]
     */
    getRoles(): string[] {
        return Object.keys(this._grants);
    }

    /**
     *  Gets the list of inherited subjects by the given subject.
     *  @name AccessControl#getInheritedRolesOf
     *  @alias AccessControl#getExtendedRolesOf
     *  @function
     *
     *  @param {string} subject - Target subject name.
     *
     *  @returns {Array<String>}
     */
    getInheritedRolesOf(subject: string): string[] {
        let subjects: string[] = utils.getRoleHierarchyOf(this._grants, subject);
        subjects.shift();
        return subjects;
    }

    /**
     *  Alias of `getInheritedRolesOf`
     *  @private
     */
    getExtendedRolesOf(subject: string): string[] {
        return this.getInheritedRolesOf(subject);
    }

    /**
     *  Gets all the unique resources that are granted access for at
     *  least one subject.
     *
     *  @returns {Array<String>}
     */
    getResources(): string[] {
        return utils.getResources(this._grants);
    }

    /**
     *  Checks whether the grants include the given subject or subjects.
     *
     *  @param {string|string[]} subject - Subject to be checked. You can also pass an
     *  array of strings to check multiple subjects at once.
     *
     *  @returns {Boolean}
     */
    hasRole(subject: string | string[]): boolean {
        if (Array.isArray(subject)) {
            return subject.every((item: string) => this._grants.hasOwnProperty(item));
        }
        return this._grants.hasOwnProperty(subject);
    }

    /**
     *  Checks whether grants include the given resource or resources.
     *
     *  @param {string|string[]} resource - Resource to be checked. You can also pass an
     *  array of strings to check multiple resources at once.
     *
     *  @returns {Boolean}
     */
    hasResource(resource: string | string[]): boolean {
        let resources = this.getResources();
        if (Array.isArray(resource)) {
            return resource.every((item: string) => resources.indexOf(item) >= 0);
        }
        if (typeof resource !== 'string' || resource === '') return false;
        return resources.indexOf(resource) >= 0;
    }

    /**
     *  Gets an instance of `Query` object. This is used to check whether the
     *  defined access is allowed for the given subject(s) and resource. This
     *  object provides chainable methods to define and query the access
     *  permissions to be checked.
     *  @name AccessControl#can
     *  @alias AccessControl#query
     *  @function
     *  @chainable
     *
     *  @param {string|Array|IQueryInfo} subject - A single subject (as a string), a
     *  list of subjects (as an array) or an
     *  {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object} that fully
     *  or partially defines the access to be checked.
     *
     *  @returns {Query} - The returned object provides chainable methods to
     *  define and query the access permissions to be checked. See
     *  {@link ?api=ac#AccessControl~Query|`Query` inner class}.
     *
     *  @example
     *  const ac = new AccessControl(grants);
     *
     *  ac.can('admin').createAny('profile');
     *  // equivalent to:
     *  ac.can().subject('admin').createAny('profile');
     *  // equivalent to:
     *  ac.can().subject('admin').resource('profile').createAny();
     *
     *  // To check for multiple subjects:
     *  ac.can(['admin', 'user']).createOwn('profile');
     *  // Note: when multiple subjects checked, acquired attributes are unioned (merged).
     */
    can(subject: string | string[] | IQueryInfo): Query {
        // throw on explicit undefined
        if (arguments.length !== 0 && subject === undefined) {
            throw new AccessControlError('Invalid subject(s): undefined');
        }
        // other explicit invalid values will be checked in constructor.
        return new Query(this._grants, subject);
    }

    /**
     *  Alias of `can()`.
     *  @private
     */
    query(subject: string | string[] | IQueryInfo): Query {
        return this.can(subject);
    }

    /**
     *  Gets an instance of `Permission` object that checks and defines the
     *  granted access permissions for the target resource and subject. Normally
     *  you would use `AccessControl#can()` method to check for permissions but
     *  this is useful if you need to check at once by passing a `IQueryInfo`
     *  object; instead of chaining methods (as in
     *  `.can(<subject>).<action>(<resource>)`).
     *
     *  @param {IQueryInfo} queryInfo - A fulfilled
     *  {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object}.
     *
     *  @returns {Permission} - An object that provides properties and methods
     *  that defines the granted access permissions. See
     *  {@link ?api=ac#AccessControl~Permission|`Permission` inner class}.
     *
     *  @example
     *  const ac = new AccessControl(grants);
     *  const permission = ac.permission({
     *      subject: "user",
     *      action: "update:own",
     *      resource: "profile"
     *  });
     *  permission.granted; // Boolean
     *  permission.attributes; // Array e.g. [ 'username', 'password', 'company.*']
     *  permission.filter(object); // { username, password, company: { name, address, ... } }
     */
    permission(queryInfo: IQueryInfo): Permission {
        return new Permission(this._grants, queryInfo);
    }

    /**
     *  Gets an instance of `Grant` (inner) object. This is used to grant access
     *  to specified resource(s) for the given subject(s).
     *  @name AccessControl#grant
     *  @alias AccessControl#allow
     *  @function
     *  @chainable
     *
     *  @param {string|Array<String>|IAccessInfo} [subject] A single subject (as a
     *  string), a list of subjects (as an array) or an
     *  {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object} that
     *  fully or partially defines the access to be granted. This can be omitted
     *  and chained with `.subject()` to define the subject.
     *
     *  @return {Access} - The returned object provides chainable properties to
     *  build and define the access to be granted. See the examples for details.
     *  See {@link ?api=ac#AccessControl~Access|`Access` inner class}.
     *
     *  @throws {AccessControlError} - If `subject` is explicitly set to an invalid value.
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     *
     *  @example
     *  const ac = new AccessControl();
     *  let attributes = ['*'];
     *
     *  ac.grant('admin').createAny('profile', attributes);
     *  // equivalent to:
     *  ac.grant().subject('admin').createAny('profile', attributes);
     *  // equivalent to:
     *  ac.grant().subject('admin').resource('profile').createAny(null, attributes);
     *  // equivalent to:
     *  ac.grant({
     *      subject: 'admin',
     *      resource: 'profile',
     *  }).createAny(null, attributes);
     *  // equivalent to:
     *  ac.grant({
     *      subject: 'admin',
     *      resource: 'profile',
     *      action: 'create:any',
     *      attributes: attributes
     *  });
     *  // equivalent to:
     *  ac.grant({
     *      subject: 'admin',
     *      resource: 'profile',
     *      action: 'create',
     *      possession: 'any', // omitting this will default to 'any'
     *      attributes: attributes
     *  });
     *
     *  // To grant same resource and attributes for multiple subjects:
     *  ac.grant(['admin', 'user']).createOwn('profile', attributes);
     *
     *  // Note: when attributes is omitted, it will default to `['*']`
     *  // which means all attributes (of the resource) are allowed.
     */
    grant(subject?: string | string[] | IAccessInfo): Access {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        // throw on explicit undefined
        if (arguments.length !== 0 && subject === undefined) {
            throw new AccessControlError('Invalid subject(s): undefined');
        }
        // other explicit invalid values will be checked in constructor.
        return new Access(this, subject, false);
    }

    /**
     *  Alias of `grant()`.
     *  @private
     */
    allow(subject?: string | string[] | IAccessInfo): Access {
        return this.grant(subject);
    }

    /**
     *  Gets an instance of `Access` object. This is used to deny access to
     *  specified resource(s) for the given subject(s). Denying will only remove a
     *  previously created grant. So if not granted before, you don't need to
     *  deny an access.
     *  @name AccessControl#deny
     *  @alias AccessControl#reject
     *  @function
     *  @chainable
     *
     *  @param {string|Array<String>|IAccessInfo} subject A single subject (as a
     *  string), a list of subjects (as an array) or an
     *  {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object} that
     *  fully or partially defines the access to be denied.
     *
     *  @return {Access} The returned object provides chainable properties to
     *  build and define the access to be granted. See
     *  {@link ?api=ac#AccessControl~Access|`Access` inner class}.
     *
     *  @throws {AccessControlError} - If `subject` is explicitly set to an invalid value.
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     *
     *  @example
     *  const ac = new AccessControl();
     *
     *  ac.deny('admin').createAny('profile');
     *  // equivalent to:
     *  ac.deny().subject('admin').createAny('profile');
     *  // equivalent to:
     *  ac.deny().subject('admin').resource('profile').createAny();
     *  // equivalent to:
     *  ac.deny({
     *      subject: 'admin',
     *      resource: 'profile',
     *  }).createAny();
     *  // equivalent to:
     *  ac.deny({
     *      subject: 'admin',
     *      resource: 'profile',
     *      action: 'create:any'
     *  });
     *  // equivalent to:
     *  ac.deny({
     *      subject: 'admin',
     *      resource: 'profile',
     *      action: 'create',
     *      possession: 'any' // omitting this will default to 'any'
     *  });
     *
     *  // To deny same resource for multiple subjects:
     *  ac.deny(['admin', 'user']).createOwn('profile');
     */
    deny(subject?: string | string[] | IAccessInfo): Access {
        if (this.isLocked) throw new AccessControlError(ERR_LOCK);
        // throw on explicit undefined
        if (arguments.length !== 0 && subject === undefined) {
            throw new AccessControlError('Invalid subject(s): undefined');
        }
        // other explicit invalid values will be checked in constructor.
        return new Access(this, subject, true);
    }

    /**
     *  Alias of `deny()`.
     *  @private
     */
    reject(subject?: string | string[] | IAccessInfo): Access {
        return this.deny(subject);
    }

    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------

    /**
     *  @private
     */
    _removePermission(resources: string | string[], subjects?: string | string[], actionPossession?: string) {
        resources = utils.toStringArray(resources);
        // resources is set but returns empty array.
        if (resources.length === 0 || !utils.isFilledStringArray(resources)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(resources)}`);
        }

        if (subjects !== undefined) {
            subjects = utils.toStringArray(subjects);
            // subjects is set but returns empty array.
            if (subjects.length === 0 || !utils.isFilledStringArray(subjects)) {
                throw new AccessControlError(`Invalid subject(s): ${JSON.stringify(subjects)}`);
            }
        }
        utils.eachRoleResource(this._grants, (subject: string, resource: string, permissions: any) => {
            if (resources.indexOf(resource) >= 0
                // subjects is optional. so remove if subject is not defined.
                // if defined, check if the current subject is in the list.
                && (!subjects || subjects.indexOf(subject) >= 0)) {
                if (actionPossession) {
                    // e.g. 'create' » 'create:any'
                    // to parse and normalize actionPossession string:
                    const ap: string = utils.normalizeActionPossession({ action: actionPossession }, true) as string;
                    // above will also validate the given actionPossession
                    delete this._grants[subject][resource][ap];
                } else {
                    // this is used for AccessControl#removeResources().
                    delete this._grants[subject][resource];
                }
            }
        });
    }

    // -------------------------------
    //  PUBLIC STATIC PROPERTIES
    // -------------------------------

    /**
     *  Documented separately in enums/Action
     *  @private
     */
    static get Action(): any {
        return Action;
    }

    /**
     *  Documented separately in enums/Possession
     *  @private
     */
    static get Possession(): any {
        return Possession;
    }

    /**
     *  Documented separately in AccessControlError
     *  @private
     */
    static get Error(): any {
        return AccessControlError;
    }

    // -------------------------------
    //  PUBLIC STATIC METHODS
    // -------------------------------

    /**
     *  A utility method for deep cloning the given data object(s) while
     *  filtering its properties by the given attribute (glob) notations.
     *  Includes all matched properties and removes the rest.
     *
     *  Note that this should be used to manipulate data / arbitrary objects
     *  with enumerable properties. It will not deal with preserving the
     *  prototype-chain of the given object.
     *
     *  @param {Object|Array} data - A single or array of data objects
     *      to be filtered.
     *  @param {Array|String} attributes - The attribute glob notation(s)
     *      to be processed. You can use wildcard stars (*) and negate
     *      the notation by prepending a bang (!). A negated notation
     *      will be excluded. Order of the globs do not matter, they will
     *      be logically sorted. Loose globs will be processed first and
     *      verbose globs or normal notations will be processed last.
     *      e.g. `[ "car.model", "*", "!car.*" ]`
     *      will be sorted as:
     *      `[ "*", "!car.*", "car.model" ]`.
     *      Passing no parameters or passing an empty string (`""` or `[""]`)
     *      will empty the source object.
     *
     *  @returns {Object|Array} - Returns the filtered data object or array
     *      of data objects.
     *
     *  @example
     *  var assets = { notebook: "Mac", car: { brand: "Ford", model: "Mustang", year: 1970, color: "red" } };
     *
     *  var filtered = AccessControl.filter(assets, [ "*", "!car.*", "car.model" ]);
     *  console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
     *
     *  filtered = AccessControl.filter(assets, "*"); // or AccessControl.filter(assets, ["*"]);
     *  console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
     *
     *  filtered = AccessControl.filter(assets); // or AccessControl.filter(assets, "");
     *  console.log(assets); // {}
     */
    static filter(data: any, attributes: string[]): any {
        return utils.filterAll(data, attributes);
    }

    /**
     *  Checks whether the given object is an instance of `AccessControl.Error`.
     *  @name AccessControl.isACError
     *  @alias AccessControl.isAccessControlError
     *  @function
     *
     *  @param {Any} object
     *         Object to be checked.
     *
     *  @returns {Boolean}
     */
    static isACError(object: any): boolean {
        return object instanceof AccessControlError;
    }

    /**
     *  Alias of `isACError`
     *  @private
     */
    static isAccessControlError(object: any): boolean {
        return AccessControl.isACError(object);
    }
}

export { AccessControl };
