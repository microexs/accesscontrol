import { IQueryInfo } from '../core';
/**
 *  Represents the inner `Permission` class that defines the granted or denied
 *  access permissions for the target resource and subject.
 *
 *  You can check for a permission in two ways:
 *
 *  <ul>
 *  <li>
 *  You can first obtain a {@link ?api=ac#AccessControl~Query|`Query` instance}
 *  via {@link ?api=ac#AccessControl#can|`AccessControl#can`} which returns
 *  a `Permission` instance when an action method such as
 *  {@link ?api=ac#AccessControl~Query#createAny|`.createAny()`} is
 *  called.
 *  <p><pre><code> var permission = ac.can('user').createAny('video');
 *  console.log(permission.granted); // boolean</code></pre></p>
 *  </li>
 *  <li>
 *  Or you can call {@link ?api=ac#AccessControl#permission|`AccessControl#permission`}
 *  by passing a fulfilled {@link ?api=ac#AccessControl#IQueryInfo|`IQueryInfo` object}.
 *  <p><pre><code> var permission = ac.permission({
 *      subject: 'user',
 *      resource: 'video',
 *      action: 'create',
 *      possession: 'any'
 *  });
 *  console.log(permission.granted); // boolean</code></pre></p>
 *  </li>
 *  </ul>
 *
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
declare class Permission {
    /**
     *  @private
     */
    private _;
    /**
     *  Initializes a new `Permission` instance.
     *  @private
     *
     *  @param {IQueryInfo} query
     *         An `IQueryInfo` arbitrary object.
     */
    constructor(grants: any, query: IQueryInfo);
    /**
     *  Specifies the subjects for which the permission is queried for.
     *  Even if the permission is queried for a single subject, this will still
     *  return an array.
     *
     *  If the returned array has multiple subjects, this does not necessarily mean
     *  that the queried permission is granted or denied for each and all subjects.
     *  Note that when a permission is queried for multiple subjects, attributes
     *  are unioned (merged) for all given subjects. This means "at least one of
     *  these subjects" have the permission for this action and resource attribute.
     *
     *  @name AccessControl~Permission#subjects
     *  @type {Array<String>}
     *  @readonly
     */
    readonly subjects: string[];
    /**
     *  Specifies the target resource for which the permission is queried for.
     *
     *  @name AccessControl~Permission#resource
     *  @type {String}
     *  @readonly
     */
    readonly resource: string;
    /**
     *  Gets an array of allowed attributes which are defined via
     *  Glob notation. If access is not granted, this will be an empty array.
     *
     *  Note that when a permission is queried for multiple subjects, attributes
     *  are unioned (merged) for all given subjects. This means "at least one of
     *  these subjects" have the permission for this action and resource attribute.
     *
     *  @name AccessControl~Permission#attributes
     *  @type {Array<String>}
     *  @readonly
     */
    readonly attributes: string[];
    /**
     *  Specifies whether the permission is granted. If `true`, this means at
     *  least one attribute of the target resource is allowed.
     *
     *  @name AccessControl~Permission#granted
     *  @type {Boolean}
     *  @readonly
     */
    readonly granted: boolean;
    /**
     *  Filters the given data object (or array of objects) by the permission
     *  attributes and returns this data with allowed attributes.
     *
     *  @param {Object|Array} data
     *         Data object to be filtered. Either a single object or array
     *         of objects.
     *
     *  @returns {Object|Array}
     *           The filtered data object.
     */
    filter(data: any): any;
}
export { Permission };
