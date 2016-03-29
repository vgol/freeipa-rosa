/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

define([
        'freeipa/ipa',
        'freeipa/jquery',
        'freeipa/datetime',
        'freeipa/util',
        'freeipa/field',
        'freeipa/widget'],
       function(IPA, $, datetime, util) {  return function() {

var old;

module('utils',{

    setup: function() {
        old = IPA.messages;
        IPA.messages = {
            widget: {
                validation: {
                    integer: "",
                    decimal: "",
                    min_value: "",
                    max_value: "",
                    pattern_errmsg: ""
                }
            }
        };
    },
    teardown: function() {
        IPA.messages = old;
    }
});

test('Testing metadata validator', function() {

    // using strings as values because it is an output of inputs

    var validator = IPA.build({
        $factory: IPA.metadata_validator
    });

    var metadata = {
        type: 'int',
        maxvalue: 300,
        minvalue: 30
    };

    var context = { metadata: metadata };

    var value;

    value = "50";
    ok(validator.validate(value, context).valid, 'Checking lower maximun, alphabetically higher');

    value = "200";
    ok(validator.validate(value, context).valid, 'Checking higher minimum, alphabetically lower');

    value = "29";
    ok(!validator.validate(value, context).valid, 'Checking below minimum');

    value = "301";
    ok(!validator.validate(value, context).valid, 'Checking above maximum');

    context.metadata.minvalue = 0;
    value = "-1";
    ok(!validator.validate(value, context).valid, 'Checking zero minimum - below');
    value = "0";
    ok(validator.validate(value, context).valid, 'Checking zero minimum - above');
    value = "1";
    ok(validator.validate(value, context).valid, 'Checking zero minimum - same');

    context.metadata = {
        type: 'int',
        maxvalue: "",
        minvalue: ""
    };

    ok(validator.validate(value, context).valid, 'Checking empty strings as boundaries');

    context.metadata = {
        type: 'int',
        maxvalue: null,
        minvalue: null
    };
    ok(validator.validate(value, context).valid, 'Checking null as boundaries');

    context.metadata = {
        type: 'int',
        maxvalue: undefined,
        minvalue: undefined
    };
    ok(validator.validate(value, context).valid, 'Checking undefined as boundaries');

    context.metadata = {
        type: 'Decimal',
        maxvalue: "10.333",
        minvalue: "-10.333"
    };

    value = "10.333";
    ok(validator.validate(value, context).valid, 'Decimal: checking maximum');
    value = "10.3331";
    ok(!validator.validate(value, context).valid, 'Decimal: checking maximum - invalid');

    value = "-10.333";
    ok(validator.validate(value, context).valid, 'Decimal: checking minimum');
    value = "-10.3331";
    ok(!validator.validate(value, context).valid, 'Decimal: checking minimum - invalid');
});

test('Testing IPA.defined', function() {

    // positive
    same(IPA.defined({}), true, 'Object');
    same(IPA.defined(0), true, 'Zero number');
    same(IPA.defined(1), true, 'Some number');
    same(IPA.defined(false), true, 'false');
    same(IPA.defined(true), true, 'true');
    same(IPA.defined(function(){}), true, 'function');
    same(IPA.defined(''), true, 'Empty string - not checking');

    // negative
    same(IPA.defined('', true), false, 'Empty string - checking');
    same(IPA.defined(undefined), false, 'undefined');
    same(IPA.defined(null), false, 'null');
});

test('Testing util.equals', function() {

    ok(util.equals([], []), 'Empty Arrays');
    ok(util.equals([1, "a", false, true], [1, "a", false, true]), 'Arrays');
    ok(util.equals(true, true), 'Boolean: true');
    ok(util.equals(false, false), 'Boolean: false');
    ok(!util.equals(true, false), 'Negative: boolean');
    ok(!util.equals(false, true), 'Negative: boolean');
    ok(util.equals("abc", "abc"), 'Positive: strings');
    ok(!util.equals("abc", "aBC"), 'Negative: string casing');
    ok(util.equals(1, 1), 'Positive: number');
    ok(util.equals(1.0, 1), 'Positive: number');
    ok(util.equals(2.2, 2.2), 'Positive: number');

    ok(!util.equals([], [""]), 'Negative: empty array');
});

test('Testing datetime', function() {

    var valid = [
        // [format, str, data, utc, output]
        [ '${YYYY}${MM}${DD}${HH}${mm}${ss}Z', '20140114175402Z', [ 2014, 1, 14, 17, 54, 2], true ],
        [ '${YYYY}-${MM}-${DD}T${HH}:${mm}:${ss}Z', '2014-01-14T17:54:02Z', [ 2014, 1, 14, 17, 54, 2], true ],
        [ '${YYYY}-${MM}-${DD} ${HH}:${mm}:${ss}Z', '2014-01-14 17:54:02Z', [ 2014, 1, 14, 17, 54, 2], true ],
        [ '${YYYY}-${MM}-${DD}T${HH}:${mm}Z', '2014-01-14T17:54Z', [ 2014, 1, 14, 17, 54, 0], true ],
        [ '${YYYY}-${MM}-${DD} ${HH}:${mm}Z', '2014-01-14 17:54Z', [ 2014, 1, 14, 17, 54, 0], true ],
        [ '${YYYY}-${MM}-${DD}', '2014-01-14', [ 2014, 1, 14, 0, 0, 0], true ],

        // allow overflows?
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/setUTCFullYear
        [ '${YYYY}-${MM}-${DD}', '2014-01-32', [ 2014, 2, 1, 0, 0, 0], true, '2014-02-01' ],
        [ '${YYYY}-${MM}-${DD}', '2014-02-30', [ 2014, 3, 2, 0, 0, 0], true, '2014-03-02' ],
        [ '${YYYY}-${MM}-${DD}', '2014-15-10', [ 2015, 3, 10, 0, 0, 0], true, '2015-03-10' ],

        // local time
        [ '${YYYY}-${MM}-${DD}T${HH}:${mm}:${ss}', '2014-01-14T17:54:13', [ 2014, 1, 14, 17, 54, 13], false ],
        [ '${YYYY}-${MM}-${DD} ${HH}:${mm}:${ss}', '2014-01-14 17:54:13', [ 2014, 1, 14, 17, 54, 13], false ],
        [ '${YYYY}-${MM}-${DD}T${HH}:${mm}', '2014-01-14T17:54', [ 2014, 1, 14, 17, 54, 0], false ],
        [ '${YYYY}-${MM}-${DD} ${HH}:${mm}', '2014-01-14 17:54', [ 2014, 1, 14, 17, 54, 0], false ]
    ];
    var invalid = [
        // [str, utc]
        ['2014-01-14T12:01:00', true],
        ['2014-01-14T12:01', true],
        ['2014-01-14T12', true],
        ['2014-01-14T12Z', true],
        ['2014-01-14TZ', true],


        ['2014-01-14 17:54:00', true],
        ['2014-01-14 17:54', true],
        ['2014-01-14 17', true],
        ['2014-01-14 17Z', true],
        ['2014-01-14Z', true],

        ['2014-01-14X17:54:00Z', true],
        ['20140114175400', false]
    ];
    var i, l;

    function test_valid(format, str, data, utc, output) {
        datetime.allow_local = !utc;
        var d = data;

        var expected = new Date();
        if (utc) {
            expected.setUTCFullYear(d[0], d[1]-1, d[2]);
            expected.setUTCHours(d[3], d[4], d[5], 0); // set ms to 0
        } else {
            expected.setFullYear(d[0], d[1]-1, d[2]);
            expected.setHours(d[3], d[4], d[5], 0); // set ms to 0
        }

        var parsed = datetime.parse(str);

        ok(parsed, "Parse successful: "+str);
        if (!parsed) return; // don't die for other tests
        strictEqual(parsed.getTime(), expected.getTime(), "Valid date: "+str);

        var formatted = datetime.format(parsed, format, !utc);
        expected = output || str;
        strictEqual(formatted, expected, "Format: "+format);
    }

    function test_invalid(str, utc) {
        datetime.allow_local = !utc;
        var parsed = datetime.parse(str);
        strictEqual(parsed, null, "Parse invalid date: "+str);
    }

    for (i=0, l=valid.length; i < l; i++) {
        test_valid(valid[i][0], valid[i][1], valid[i][2], valid[i][3], valid[i][4]);
    }

    for (i=0, l=invalid.length; i < l; i++) {
        test_invalid(invalid[i][0], invalid[i][1]);
    }
});

};});