import { AccessControl } from '../';
import { IAccessInfo, AccessControlError } from '../core';
import { utils } from '../utils';
import { Possession } from '../enums/Possession';

/**
 *  Represents the inner `Access` class that helps build an access information
 *  to be granted or denied; and finally commits it to the underlying grants
 *  model. You can get a first instance of this class by calling
 *  `AccessControl#grant()` or `AccessControl#deny()` methods.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
class Access {

    /**
     *  Inner `IAccessInfo` object.
     *  @protected
     *  @type {IAccessInfo}
     */
    protected _: IAccessInfo = {};

    /**
     *  Main grants object.
     *  @protected
     *  @type {AccessControl}
     */
    protected _ac: AccessControl;

    /**
     *  Main grants object.
     *  @protected
     *  @type {Any}
     */
    protected _grants: any;

    /**
     *  Initializes a new instance of `Access`.
     *  @private
     *
     *  @param {AccessControl} ac
     *         AccessControl instance.
     *  @param {String|Array<String>|IAccessInfo} [subjectOrInfo]
     *         Either an `IAccessInfo` object, a single or an array of
     *         subjects. If an object is passed, possession and attributes
     *         properties are optional. CAUTION: if attributes is omitted,
     *         and access is not denied, it will default to `["*"]` which means
     *         "all attributes allowed". If possession is omitted, it will
     *         default to `"any"`.
     *  @param {Boolean} denied
     *         Specifies whether this `Access` is denied.
     */
    constructor(ac: AccessControl, subjectOrInfo?: string | string[] | IAccessInfo, denied: boolean = false) {
        this._ac = ac;
        this._grants = (ac as any)._grants;
        this._.denied = denied;

        if (typeof subjectOrInfo === 'string' || Array.isArray(subjectOrInfo)) {
            this.subject(subjectOrInfo);
        } else if (utils.type(subjectOrInfo) === 'object') {
            if (Object.keys(subjectOrInfo).length === 0) {
                throw new AccessControlError('Invalid IAccessInfo: {}');
            }
            // if an IAccessInfo instance is passed and it has 'action' defined, we
            // should directly commit it to grants.
            subjectOrInfo.denied = denied;
            this._ = utils.resetAttributes(subjectOrInfo);
            if (utils.isInfoFulfilled(this._)) utils.commitToGrants(this._grants, this._, true);
        } else if (subjectOrInfo !== undefined) {
            // undefined is allowed (`subjectOrInfo` can be omitted) but throw if
            // some other type is passed.
            throw new AccessControlError('Invalid subject(s), expected a valid string, string[] or IAccessInfo.');
        }
    }

    // -------------------------------
    //  PUBLIC PROPERTIES
    // -------------------------------

    /**
     *  Specifies whether this access is initally denied.
     *  @name AccessControl~Access#denied
     *  @type {Boolean}
     *  @readonly
     */
    get denied(): boolean {
        return this._.denied;
    }

    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------

    /**
     *  A chainer method that sets the subject(s) for this `Access` instance.
     *  @param {String|Array<String>} value
     *         A single or array of subjects.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    subject(value: string | string[]): Access {
        // in case chain is not terminated (e.g. `ac.grant('user')`) we'll
        // create/commit the subjects to grants with an empty object.
        utils.preCreateRoles(this._grants, value);

        this._.subject = value;
        return this;
    }

    /**
     *  A chainer method that sets the resource for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Target resource for this `Access` instance.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    resource(value: string | string[]): Access {
        // this will throw if any item fails
        utils.hasValidNames(value, true);
        this._.resource = value;
        return this;
    }

    /**
     *  Sets the array of allowed attributes for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Attributes to be set.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    attributes(value: string | string[]): Access {
        this._.attributes = value;
        return this;
    }

    /**
     *  Sets the subjects to be extended for this `Access` instance.
     *  @alias Access#inherit
     *  @name AccessControl~Access#extend
     *  @function
     *
     *  @param {String|Array<String>} subjects
     *         A single or array of subjects.
     *  @returns {Access}
     *           Self instance of `Access`.
     *
     *  @example
     *  ac.grant('user').createAny('video')
     *    .grant('admin').extend('user');
     *  const permission = ac.can('admin').createAny('video');
     *  console.log(permission.granted); // true
     */
    extend(subjects: string | string[]): Access {
        utils.extendRole(this._grants, this._.subject, subjects, false);
        return this;
    }

    /**
     *  Alias of `extend`.
     *  @private
     */
    inherit(subjects: string | string[]): Access {
        this.extend(subjects);
        return this;
    }

    /**
     *  Shorthand to switch to a new `Access` instance with a different subject
     *  within the method chain.
     *
     *  @param {String|Array<String>|IAccessInfo} [subjectOrInfo]
     *         Either a single or an array of subjects or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}.
     *
     *  @returns {Access}
     *           A new `Access` instance.
     *
     *  @example
     *  ac.grant('user').createOwn('video')
     *    .grant('admin').updateAny('video');
     */
    grant(subjectOrInfo?: string | string[] | IAccessInfo): Access {
        return (new Access(this._ac, subjectOrInfo, false)).attributes(['*']);
    }

    /**
     *  Shorthand to switch to a new `Access` instance with a different
     *  (or same) subject within the method chain.
     *
     *  @param {String|Array<String>|IAccessInfo} [subjectOrInfo]
     *         Either a single or an array of subjects or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}.
     *
     *  @returns {Access}
     *           A new `Access` instance.
     *
     *  @example
     *  ac.grant('admin').createAny('video')
     *    .deny('user').deleteAny('video');
     */
    deny(subjectOrInfo?: string | string[] | IAccessInfo): Access {
        return (new Access(this._ac, subjectOrInfo, true)).attributes([]);
    }

    /**
     *  Chainable, convenience shortcut for {@link ?api=ac#AccessControl#lock|`AccessControl#lock()`}.
     *  @returns {Access}
     */
    lock(): Access {
        utils.lockAC(this._ac);
        return this;
    }

    /**
     *  Sets the action to `"create"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid
     *  data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    createOwn(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit('create', 'own', resource, attributes);
    }

    /**
     *  Sets the action to `"create"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#create
     *  @name AccessControl~Access#createAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    createAny(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit('create', 'any', resource, attributes);
    }
    /**
     *  Alias of `createAny`
     *  @private
     */
    create(resource?: string | string[], attributes?: string | string[]): Access {
        return this.createAny(resource, attributes);
    }

    /**
     *  Sets the action to `"read"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    readOwn(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit('read', 'own', resource, attributes);
    }

    /**
     *  Sets the action to `"read"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#read
     *  @name AccessControl~Access#readAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    readAny(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit('read', 'any', resource, attributes);
    }
    /**
     *  Alias of `readAny`
     *  @private
     */
    read(resource?: string | string[], attributes?: string | string[]): Access {
        return this.readAny(resource, attributes);
    }

    /**
     *  Sets the action to `"update"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    updateOwn(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit('update', 'own', resource, attributes);
    }

    /**
     *  Sets the action to `"update"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#update
     *  @name AccessControl~Access#updateAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    updateAny(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit('update', 'any', resource, attributes);
    }
    /**
     *  Alias of `updateAny`
     *  @private
     */
    update(resource?: string | string[], attributes?: string | string[]): Access {
        return this.updateAny(resource, attributes);
    }

    /**
     *  Sets the action to `"delete"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    deleteOwn(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit('delete', 'own', resource, attributes);
    }

    /**
     *  Sets the action to `"delete"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#delete
     *  @name AccessControl~Access#deleteAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    deleteAny(resource?: string | string[], attributes?: string | string[]): Access {
        return this._prepareAndCommit('delete', 'any', resource, attributes);
    }
    /**
     *  Alias of `deleteAny`
     *  @private
     */
    delete(resource?: string | string[], attributes?: string | string[]): Access {
        return this.deleteAny(resource, attributes);
    }

    /**
     *  @param {String} action     [description]
     *  @param {String|Array<String>} resource   [description]
     *  @param {String|Array<String>} attributes [description]
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    public do(action: string, attributes?: string | string[]): Access {
        let segments = action.split(':');
        return this._prepareAndCommit(segments[1], segments[2] as Possession, segments[0], attributes)
    }

    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------

    /**
     *  @private
     *  @param {String} action     [description]
     *  @param {String} possession [description]
     *  @param {String|Array<String>} resource   [description]
     *  @param {String|Array<String>} attributes [description]
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    private _prepareAndCommit(action: string, possession: Possession, resource?: string | string[], attributes?: string | string[]): Access {
        this._.action = action;
        this._.possession = possession;
        if (resource) this._.resource = resource;

        if (this._.denied) {
            this._.attributes = [];
        } else {
            // if omitted and not denied, all attributes are allowed
            this._.attributes = attributes ? utils.toStringArray(attributes) : ['*'];
        }

        utils.commitToGrants(this._grants, this._, false);

        // important: reset attributes for chained methods
        this._.attributes = undefined;

        return this;
    }

}

export { Access };
