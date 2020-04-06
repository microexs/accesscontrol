<h1 align="center">
    <a href="https://github.com/onury/accesscontrol"><img width="465" height="170" src="https://raw.github.com/onury/accesscontrol/master/ac-logo.png" alt="AccessControl.js" /></a>
</h1>
<p align="center">
    <a href="https://travis-ci.org/onury/accesscontrol"><img src="https://img.shields.io/travis/onury/accesscontrol.svg?branch=master&style=flat-square" alt="Build Status" /></a>
    <a href="https://coveralls.io/github/onury/accesscontrol?branch=master"><img src="https://img.shields.io/coveralls/github/onury/accesscontrol/master.svg?style=flat-square" alt="Coverage Status" /></a>
    <a href="https://david-dm.org/onury/accesscontrol"><img src="https://david-dm.org/onury/accesscontrol.svg?style=flat-square" alt="Dependencies" /></a>
    <a href="https://snyk.io/test/github/onury/accesscontrol"><img src="https://snyk.io/test/github/onury/accesscontrol/badge.svg?style=flat-square" alt="Known Vulnerabilities" /></a>
    <a href="https://nodesecurity.io/orgs/onury/projects/1db2347a-c83a-4c13-b485-ed552f43046f"><img src="https://nodesecurity.io/orgs/onury/projects/1db2347a-c83a-4c13-b485-ed552f43046f/badge?style=flat-square" alt="NSP Status" /></a>
    <a href="https://github.com/onury/accesscontrol/graphs/commit-activity"><img src="https://img.shields.io/maintenance/yes/2019.svg?style=flat-square" alt="Maintained" /></a>
    <br />
    <a href="https://www.npmjs.com/package/accesscontrol"><img src="http://img.shields.io/npm/v/accesscontrol.svg?style=flat-square" alt="npm" /></a>
    <a href="https://github.com/onury/accesscontrol"><img src="https://img.shields.io/github/release/onury/accesscontrol.svg?style=flat-square" alt="Release" /></a>
    <a href="https://www.npmjs.com/package/accesscontrol"><img src="http://img.shields.io/npm/dm/accesscontrol.svg?style=flat-square" alt="Downloads/mo." /></a>
    <a href="https://github.com/onury/accesscontrol/blob/master/LICENSE"><img src="http://img.shields.io/npm/l/accesscontrol.svg?style=flat-square" alt="License" /></a>
    <a href="https://www.typescriptlang.org"><img src="https://img.shields.io/badge/written%20in-%20TypeScript%20-6575ff.svg?style=flat-square" alt="TypeScript" /></a>
    <a href="https://onury.io/accesscontrol/?api=ac"><img src="https://img.shields.io/badge/documentation-click_to_read-c27cf4.svg?documentation=click_to_read&style=flat-square" alt="Documentation" /></a>
    <br />
    <sub>© 2019, Onur Yıldırım (<b><a href="https://github.com/onury">@onury</a></b>).</sub>
</p>
<br />


### Subject and Attribute based Access Control for Node.js  

Many [RBAC][rbac] (Subject-Based Access Control) implementations differ, but the basics is widely adopted since it simulates real life subject (job) assignments. But while data is getting more and more complex; you need to define policies on resources, subjects or even environments. This is called [ABAC][abac] (Attribute-Based Access Control).

With the idea of merging the best features of the two (see this [NIST paper][nist-paper]); this library implements RBAC basics and also focuses on *resource* and *action* attributes.

<table>
  <thead>
    <tr>
      <th><a href="#installation">Install</a></th>
      <th><a href="#guide">Examples</a></th>
      <th><a href="#subjects">Subjects</a></th>
      <th><a href="#actions-and-action-attributes">Actions</a></th>
      <th><a href="#resources-and-resource-attributes">Resources</a></th>
      <th><a href="#checking-permissions-and-filtering-attributes">Permissions</a></th>
      <th><a href="#defining-all-grants-at-once">More</a></th>
      <th><a href="https://github.com/onury/accesscontrol/blob/master/docs/FAQ.md">F.A.Q.</a></th>
      <th><a href="https://onury.io/accesscontrol?api=ac">API Reference</a></th>
    </tr>
  </thead>
</table>

## Core Features

- Chainable, friendly API.  
e.g. `ac.can(subject).create(resource)`
- Subject hierarchical **inheritance**.
- Define grants **at once** (e.g. from database result) or **one by one**.
- Grant/deny permissions by attributes defined by **glob notation** (with nested object support).
- Ability to **filter** data (model) instance by allowed attributes.
- Ability to control access on **own** or **any** resources.
- Ability to **lock** underlying grants model.
- No **silent** errors.
- **Fast**. (Grants are stored in memory, no database queries.)
- Brutally **tested**.
- TypeScript support.

_In order to build on more solid foundations, this library (v1.5.0+) is completely re-written in TypeScript._

## Installation

with [**npm**](https://www.npmjs.com/package/accesscontrol): `npm i accesscontrol --save`  
with [**yarn**](https://yarn.pm/accesscontrol): `yarn add accesscontrol`

## Guide

```js
const AccessControl = require('accesscontrol');
// or:
// import { AccessControl } from 'accesscontrol';
```

### Basic Example

Define subjects and grants one by one.
```js
const ac = new AccessControl();
ac.grant('user')                    // define new or modify existing subject. also takes an array.
    .createOwn('video')             // equivalent to .createOwn('video', ['*'])
    .deleteOwn('video')
    .readAny('video')
  .grant('admin')                   // switch to another subject without breaking the chain
    .extend('user')                 // inherit subject capabilities. also takes an array
    .updateAny('video', ['title'])  // explicitly defined attributes
    .deleteAny('video');

const permission = ac.can('user').createOwn('video');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*'] (all attributes)

permission = ac.can('admin').updateAny('video');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['title']
```

### Express.js Example

Check subject permissions for the requested resource and action, if granted; respond with filtered attributes.

```js
const ac = new AccessControl(grants);
// ...
router.get('/videos/:title', function (req, res, next) {
    const permission = ac.can(req.user.subject).readAny('video');
    if (permission.granted) {
        Video.find(req.params.title, function (err, data) {
            if (err || !data) return res.status(404).end();
            // filter data by permission attributes and send.
            res.json(permission.filter(data));
        });
    } else {
        // resource is forbidden for this user/subject
        res.status(403).end();
    }
});
```

## Subjects

You can create/define subjects simply by calling `.grant(<subject>)` or `.deny(<subject>)` methods on an `AccessControl` instance.  

- Subjects can extend other subjects.

```js
// user subject inherits viewer subject permissions
ac.grant('user').extend('viewer');
// admin subject inherits both user and editor subject permissions
ac.grant('admin').extend(['user', 'editor']);
// both admin and superadmin subjects inherit moderator permissions
ac.grant(['admin', 'superadmin']).extend('moderator');
```

- Inheritance is done by reference, so you can grant resource permissions before or after extending a subject. 

```js
// case #1
ac.grant('admin').extend('user') // assuming user subject already exists
  .grant('user').createOwn('video');

// case #2
ac.grant('user').createOwn('video')
  .grant('admin').extend('user');

// below results the same for both cases
const permission = ac.can('admin').createOwn('video');
console.log(permission.granted); // true
```

Notes on inheritance:  
- A subject cannot extend itself.
- Cross-inheritance is not allowed.  
e.g. `ac.grant('user').extend('admin').grant('admin').extend('user')` will throw.
- A subject cannot (pre)extend a non-existing subject. In other words, you should first create the base subject.  e.g. `ac.grant('baseRole').grant('subject').extend('baseRole')`

## Actions and Action-Attributes

[CRUD][crud] operations are the actions you can perform on a resource. There are two action-attributes which define the **possession** of the resource: *own* and *any*.

For example, an `admin` subject can `create`, `read`, `update` or `delete` (CRUD) **any** `account` resource. But a `user` subject might only `read` or `update` its **own** `account` resource.

<table>
    <thead>
        <tr>
            <th>Action</th>
            <th>Possession</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td rowspan="2">
            <b>C</b>reate<br />
            <b>R</b>ead<br />
            <b>U</b>pdate<br />
            <b>D</b>elete<br />
            </td>
            <td>Own</td>
            <td>The C|R|U|D action is (or not) to be performed on own resource(s) of the current subject.</td>
        </tr>
        <tr>
            <td>Any</td>
            <td>The C|R|U|D action is (or not) to be performed on any resource(s); including own.</td>
        </tr>   
    </tbody>
</table>

```js
ac.grant('subject').readOwn('resource');
ac.deny('subject').deleteAny('resource');
```

_Note that **own** requires you to also check for the actual possession. See [this](https://github.com/onury/accesscontrol/issues/14#issuecomment-328316670) for more._

## Resources and Resource-Attributes

Multiple subjects can have access to a specific resource. But depending on the context, you may need to limit the contents of the resource for specific subjects.  

This is possible by resource attributes. You can use Glob notation to define allowed or denied attributes.

For example, we have a `video` resource that has the following attributes: `id`, `title` and `runtime`.
All attributes of *any* `video` resource can be read by an `admin` subject:
```js
ac.grant('admin').readAny('video', ['*']);
// equivalent to:
// ac.grant('admin').readAny('video');
```
But the `id` attribute should not be read by a `user` subject.  
```js
ac.grant('user').readOwn('video', ['*', '!id']);
// equivalent to:
// ac.grant('user').readOwn('video', ['title', 'runtime']);
```

You can also use nested objects (attributes).
```js
ac.grant('user').readOwn('account', ['*', '!record.id']);
```

## Checking Permissions and Filtering Attributes

You can call `.can(<subject>).<action>(<resource>)` on an `AccessControl` instance to check for granted permissions for a specific resource and action.

```js
const permission = ac.can('user').readOwn('account');
permission.granted;       // true
permission.attributes;    // ['*', '!record.id']
permission.filter(data);  // filtered data (without record.id)
```
See [express.js example](#expressjs-example).

## Defining All Grants at Once

You can pass the grants directly to the `AccessControl` constructor.
It accepts either an `Object`:

```js
// This is actually how the grants are maintained internally.
let grantsObject = {
    admin: {
        video: {
            'create:any': ['*', '!views'],
            'read:any': ['*'],
            'update:any': ['*', '!views'],
            'delete:any': ['*']
        }
    },
    user: {
        video: {
            'create:own': ['*', '!rating', '!views'],
            'read:own': ['*'],
            'update:own': ['*', '!rating', '!views'],
            'delete:own': ['*']
        }
    }
};
const ac = new AccessControl(grantsObject);
```
... or an `Array` (useful when fetched from a database):
```js
// grant list fetched from DB (to be converted to a valid grants object, internally)
let grantList = [
    { subject: 'admin', resource: 'video', action: 'create:any', attributes: '*, !views' },
    { subject: 'admin', resource: 'video', action: 'read:any', attributes: '*' },
    { subject: 'admin', resource: 'video', action: 'update:any', attributes: '*, !views' },
    { subject: 'admin', resource: 'video', action: 'delete:any', attributes: '*' },

    { subject: 'user', resource: 'video', action: 'create:own', attributes: '*, !rating, !views' },
    { subject: 'user', resource: 'video', action: 'read:any', attributes: '*' },
    { subject: 'user', resource: 'video', action: 'update:own', attributes: '*, !rating, !views' },
    { subject: 'user', resource: 'video', action: 'delete:own', attributes: '*' }
];
const ac = new AccessControl(grantList);
```
You can set grants any time...
```js
const ac = new AccessControl();
ac.setGrants(grantsObject);
console.log(ac.getGrants());
```
...unless you lock it:
```js
ac.lock().setGrants({}); // throws after locked
```

## Documentation

You can read the full [**API reference**][docs] with lots of details, features and examples.  
And more at the [F.A.Q. section][faq].

## Change-Log

See [CHANGELOG][changelog].

## Contributing

Clone original project:

```sh
git clone https://github.com/onury/accesscontrol.git
```

Install dependencies:

```sh
npm install
```

Add tests to relevant file under [/test](test/) directory and run:  

```sh
npm run build && npm run cover
```

Use included `tslint.json` and `editorconfig` for style and linting.  
Travis build should pass, coverage should not degrade.

## License

[**MIT**][license].

[docs]:http://onury.io/accesscontrol/?api=ac
[faq]:http://onury.io/accesscontrol/?content=faq
[rbac]:https://en.wikipedia.org/wiki/Subject-based_access_control
[abac]:https://en.wikipedia.org/wiki/Attribute-Based_Access_Control
[crud]:https://en.wikipedia.org/wiki/Create,_read,_update_and_delete
[nist-paper]:http://csrc.nist.gov/groups/SNS/rbac/documents/kuhn-coyne-weil-10.pdf
[changelog]:https://github.com/onury/accesscontrol/blob/master/CHANGELOG.md
[license]:https://github.com/onury/accesscontrol/blob/master/LICENSE
