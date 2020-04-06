/**
 *  Enumerates the possible actions of a subject.
 *  An action defines the type of an operation that will be executed on a
 *  "resource" by a "subject".
 *  This is known as CRUD (CREATE, READ, UPDATE, DELETE).
 *  @enum {String}
 *  @readonly
 *  @memberof! AccessControl
 */
declare const Action: {
    CREATE: string;
    READ: string;
    UPDATE: string;
    DELETE: string;
};
export { Action };
