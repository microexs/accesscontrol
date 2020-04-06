import { AccessControl } from './';
import { IAccessInfo, IQueryInfo } from './core';
/**
 *  List of reserved keywords.
 *  i.e. Subjects, resources with these names are not allowed.
 */
declare const RESERVED_KEYWORDS: string[];
/**
 *  Error message to be thrown after AccessControl instance is locked.
 */
declare const ERR_LOCK = "Cannot alter the underlying grants model. AccessControl instance is locked.";
declare const utils: {
    type(o: any): string;
    hasDefined(o: any, propName: string): boolean;
    toStringArray(value: any): string[];
    isFilledStringArray(arr: any[]): boolean;
    isEmptyArray(value: any): boolean;
    pushUniq(arr: string[], item: string): string[];
    uniqConcat(arrA: string[], arrB: string[]): string[];
    subtractArray(arrA: string[], arrB: string[]): string[];
    deepFreeze(o: any): any;
    each(array: any, callback: any, thisArg?: any): void;
    eachKey(object: any, callback: any, thisArg?: any): void;
    eachRole(grants: any, callback: (subject: any, subjectName: string) => void): void;
    eachRoleResource(grants: any, callback: (subject: string, resource: string, resourceDefinition: any) => void): void;
    isInfoFulfilled(info: IAccessInfo | IQueryInfo): boolean;
    validName(name: string, throwOnInvalid?: boolean): boolean;
    hasValidNames(list: any, throwOnInvalid?: boolean): boolean;
    validResourceObject(o: any): boolean;
    validRoleObject(grants: any, subjectName: string): boolean;
    getInspectedGrants(o: any): any;
    getResources(grants: any): string[];
    normalizeActionPossession(info: IAccessInfo | IQueryInfo, asString?: boolean): string | IAccessInfo | IQueryInfo;
    normalizeQueryInfo(query: IQueryInfo): IQueryInfo;
    normalizeAccessInfo(access: IAccessInfo, all?: boolean): IAccessInfo;
    resetAttributes(access: IAccessInfo): IAccessInfo;
    getRoleHierarchyOf(grants: any, subjectName: string, rootRole?: string): string[];
    getFlatRoles(grants: any, subjects: string | string[]): string[];
    getNonExistentRoles(grants: any, subjects: string[]): string[];
    getCrossExtendingRole(grants: any, subjectName: string, extenderRoles: string | string[]): string;
    extendRole(grants: any, subjects: string | string[], extenderRoles: string | string[]): void;
    preCreateRoles(grants: any, subjects: string | string[]): void;
    commitToGrants(grants: any, access: IAccessInfo, normalizeAll?: boolean): void;
    getUnionAttrsOfRoles(grants: any, query: IQueryInfo): string[];
    lockAC(ac: AccessControl): void;
    filter(object: any, attributes: string[]): any;
    filterAll(arrOrObj: any, attributes: string[]): any;
};
export { utils, RESERVED_KEYWORDS, ERR_LOCK };
