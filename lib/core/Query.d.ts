import { IQueryInfo, Permission } from '../core';
/**
 *  Represents the inner `Query` class that helps build an access information
 *  for querying and checking permissions, from the underlying grants model.
 *  You can get a first instance of this class by calling
 *  `AccessControl#can(<subject>)` method.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
declare class Query {
    /**
     *  Inner `IQueryInfo` object.
     *  @protected
     *  @type {IQueryInfo}
     */
    protected _: IQueryInfo;
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
    constructor(grants: any, subjectOrInfo?: string | string[] | IQueryInfo);
    /**
     *  A chainer method that sets the subject(s) for this `Query` instance.
     *  @param {String|Array<String>} subjects
     *         A single or array of subjects.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    subject(subject: string | string[]): Query;
    /**
     *  A chainer method that sets the resource for this `Query` instance.
     *  @param {String} resource
     *         Target resource for this `Query` instance.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    resource(resource: string): Query;
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
    createOwn(resource?: string): Permission;
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
    createAny(resource?: string): Permission;
    /**
     *  Alias if `createAny`
     *  @private
     */
    create(resource?: string): Permission;
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
    readOwn(resource?: string): Permission;
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
    readAny(resource?: string): Permission;
    /**
     *  Alias if `readAny`
     *  @private
     */
    read(resource?: string): Permission;
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
    updateOwn(resource?: string): Permission;
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
    updateAny(resource?: string): Permission;
    /**
     *  Alias if `updateAny`
     *  @private
     */
    update(resource?: string): Permission;
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
    deleteOwn(resource?: string): Permission;
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
    deleteAny(resource?: string): Permission;
    /**
     *  Alias if `deleteAny`
     *  @private
     */
    delete(resource?: string): Permission;
    /**
     *  @private
     *  @param {String} action
     *  @param {String} possession
     *  @param {String} [resource]
     *  @returns {Permission}
     */
    do(action: string): Permission;
    /**
     *  @private
     *  @param {String} action
     *  @param {String} possession
     *  @param {String} [resource]
     *  @returns {Permission}
     */
    private _getPermission;
}
export { Query };
