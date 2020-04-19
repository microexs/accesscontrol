/**
 *  Enumerates the possible actions of a subject.
 *  An action defines the type of an operation that will be executed on a
 *  "resource" by a "subject".
 *  This is known as CRUD (CREATE, READ, UPDATE, DELETE).
 *  @enum {String}
 *  @readonly
 *  @memberof! AccessControl
 */
export type Action = 'create' | 'read' | 'update' | 'delete';
