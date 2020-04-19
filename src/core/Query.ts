import { IQueryInfo, Permission, AccessControlError } from '../core';
import { utils } from '../utils';
import { Possession } from '../enums/Possession';

/**
 *  Represents the inner `Query` class that helps build an access information
 *  for querying and checking permissions, from the underlying grants model.
 *  You can get a first instance of this class by calling
 *  `AccessControl#can(<subject>)` method.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
class Query {

    /**
     *  Inner `IQueryInfo` object.
     *  @protected
     *  @type {IQueryInfo}
     */
    protected _: IQueryInfo = {};

    /**
     *  Main grants object.
     *  @protected
     *  @type {Any}
     */
    protected _grants: any;

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
    constructor(grants: any, subjectOrInfo?: string | string[] | IQueryInfo) {
        this._grants = grants;

        if (typeof subjectOrInfo === 'string' || Array.isArray(subjectOrInfo)) {
            // if this is just subject(s); a string or array; we start building
            // the grant object for this.
            this.subject(subjectOrInfo);
        } else if (utils.type(subjectOrInfo) === 'object') {
            // if this is a (permission) object, we directly build attributes
            // from grants.
            if (Object.keys(subjectOrInfo).length === 0) {
                throw new AccessControlError('Invalid IQueryInfo: {}');
            }
            this._ = subjectOrInfo as IQueryInfo;
        } else if (subjectOrInfo !== undefined) {
            // undefined is allowed (`subject` can be omitted) but throw if some
            // other type is passed.
            throw new AccessControlError('Invalid subject(s), expected a valid string, string[] or IQueryInfo.');
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
    subject(subject: string | string[]): Query {
        this._.subject = subject;
        return this;
    }

    /**
     *  A chainer method that sets the resource for this `Query` instance.
     *  @param {String} resource
     *         Target resource for this `Query` instance.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    resource(resource: string): Query {
        this._.resource = resource;
        return this;
    }

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
    createOwn(resource?: string): Permission {
        return this._getPermission('create', 'own', resource);
    }

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
    createAny(resource?: string): Permission {
        return this._getPermission('create', 'any', resource);
    }
    /**
     *  Alias if `createAny`
     *  @private
     */
    create(resource?: string): Permission {
        return this.createAny(resource);
    }

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
    readOwn(resource?: string): Permission {
        return this._getPermission('read', 'own', resource);
    }

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
    readAny(resource?: string): Permission {
        return this._getPermission('read', 'any', resource);
    }
    /**
     *  Alias if `readAny`
     *  @private
     */
    read(resource?: string): Permission {
        return this.readAny(resource);
    }

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
    updateOwn(resource?: string): Permission {
        return this._getPermission('update', 'own', resource);
    }

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
    updateAny(resource?: string): Permission {
        return this._getPermission('update', 'any', resource);
    }
    /**
     *  Alias if `updateAny`
     *  @private
     */
    update(resource?: string): Permission {
        return this.updateAny(resource);
    }

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
    deleteOwn(resource?: string): Permission {
        return this._getPermission('delete', 'own', resource);
    }

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
    deleteAny(resource?: string): Permission {
        return this._getPermission('delete', 'any', resource);
    }
    /**
     *  Alias if `deleteAny`
     *  @private
     */
    delete(resource?: string): Permission {
        return this.deleteAny(resource);
    }

    /**
     *  @private
     *  @param {String} action
     *  @param {String} possession
     *  @param {String} [resource]
     *  @returns {Permission}
     */
    public do(action: string): Permission {
        let segments = action.split(':');
        return this._getPermission(segments[1], segments[2] as Possession, segments[0])
    }

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
    private _getPermission(action: string, possession: Possession, resource?: string): Permission {
        this._.action = action;
        this._.possession = possession;
        if (resource) this._.resource = resource;
        return new Permission(this._grants, this._);
    }
}

export { Query };
