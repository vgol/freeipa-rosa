/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
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
    'dojo/_base/declare',
    './field',
    './ipa',
    './jquery',
    './phases',
    './reg',
    './rpc',
    './text',
    './details',
    './search',
    './association',
    './entity'],
        function(declare, field_mod, IPA, $, phases, reg, rpc, text) {

var exp =IPA.service = {};

var make_spec = function() {
return {
    name: 'service',
    policies: [
        IPA.search_facet_update_policy,
        IPA.details_facet_update_policy,
        {
            $factory: IPA.cert.cert_update_policy,
            source_facet: 'details',
            dest_entity: 'cert',
            dest_facet: 'details'
        },
        {
            $factory: IPA.cert.cert_update_policy,
            source_facet: 'details',
            dest_entity: 'cert',
            dest_facet: 'search'
        }
    ],
    facets: [
        {
            $type: 'search',
            columns: [ 'krbprincipalname' ]
        },
        {
            $type: 'details',
            $factory: IPA.service.details_facet,
            sections: [
                {
                    name: 'details',
                    fields: [
                        'krbprincipalname',
                        {
                            name: 'service',
                            label: '@i18n:objects.service.service',
                            read_only: true,
                            adapter: IPA.service_name_adapter
                        },
                        {
                            name: 'host',
                            label: '@i18n:objects.service.host',
                            read_only: true,
                            adapter: IPA.service_host_adapter
                        },
                        {
                            name: 'ipakrbauthzdata',
                            $type: 'radio',
                            layout: 'vertical',
                            options: [
                                {
                                    label: '@i18n:krbauthzdata.inherited',
                                    value: ''
                                },
                                {
                                    label: '@i18n:krbauthzdata.override',
                                    name: 'ipakrbauthzdata_override',
                                    $factory: IPA.option_widget_base,
                                    input_type: 'checkbox',
                                    value: 'NONE',
                                    combine_values: false,
                                    options: [
                                        {
                                            label: '@i18n:krbauthzdata.mspac',
                                            value: 'MS-PAC'
                                        },
                                        {
                                            label: '@i18n:krbauthzdata.pad',
                                            value: 'PAD'
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            name: 'ipakrbokasdelegate',
                            $type: 'checkbox',
                            acl_param: 'krbticketflags'
                        },
                        {
                            name: 'ipakrbrequirespreauth',
                            $type: 'checkbox',
                            acl_param: 'krbticketflags'
                        }
                    ]
                },
                {
                    name: 'provisioning',
                    fields: [
                        {
                            $type: 'service_provisioning_status',
                            name: 'has_keytab',
                            label: '@i18n:objects.service.status'
                        }
                    ]
                },
                {
                    name: 'certificate',
                    fields: [
                        {
                            $type: 'certificate',
                            name: 'usercertificate'
                        }
                    ]
                },
                {
                    $factory: IPA.section,
                    name: 'divider',
                    layout_css_class: 'col-sm-12',
                    fields: []
                },
                {
                    name: 'read',
                    label: '@i18n:keytab.allowed_to_retrieve',
                    $factory: IPA.section,
                    fields: [
                        {
                            $type: 'association_table',
                            id: 'service_ipaallowedtoperform_read_keys_user',
                            name: 'ipaallowedtoperform_read_keys_user',
                            add_method: 'allow_retrieve_keytab',
                            remove_method: 'disallow_retrieve_keytab',
                            add_title: '@i18n:keytab.add_retrive',
                            remove_title: '@i18n:keytab.remove_retrieve',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_read_keys_user',
                                    label: '@mo:user.label_singular',
                                    link: true
                                }
                            ]
                        },
                        {
                            $type: 'association_table',
                            id: 'service_ipaallowedtoperform_read_keys_group',
                            name: 'ipaallowedtoperform_read_keys_group',
                            add_method: 'allow_retrieve_keytab',
                            remove_method: 'disallow_retrieve_keytab',
                            add_title: '@i18n:keytab.add_retrive',
                            remove_title: '@i18n:keytab.remove_retrieve',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_read_keys_group',
                                    label: '@mo:group.label_singular',
                                    link: true
                                }
                            ]
                        }
                    ]
                },
                {
                    name: 'write',
                    label: '@i18n:keytab.allowed_to_create',
                    $factory: IPA.section,
                    fields: [
                        {
                            $type: 'association_table',
                            id: 'service_ipaallowedtoperform_write_keys_user',
                            name: 'ipaallowedtoperform_write_keys_user',
                            add_method: 'allow_create_keytab',
                            remove_method: 'disallow_create_keytab',
                            add_title: '@i18n:keytab.add_create',
                            remove_title: '@i18n:keytab.remove_create',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_write_keys_user',
                                    label: '@mo:user.label_singular',
                                    link: true
                                }
                            ]
                        },
                        {
                            $type: 'association_table',
                            id: 'service_ipaallowedtoperform_write_keys_group',
                            name: 'ipaallowedtoperform_write_keys_group',
                            add_method: 'allow_create_keytab',
                            remove_method: 'disallow_create_keytab',
                            add_title: '@i18n:keytab.add_create',
                            remove_title: '@i18n:keytab.remove_create',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_write_keys_group',
                                    label: '@mo:group.label_singular',
                                    link: true
                                }
                            ]
                        }
                    ]
                }
            ],
            actions: [
                'service_unprovision',
                'cert_request'
            ],
            header_actions: [
                'unprovision',
                'request_cert'
            ],
            state: {
                evaluators: [
                    IPA.service.has_keytab_evaluator,
                    IPA.service.krbprincipalkey_acl_evaluator,
                    IPA.cert.certificate_evaluator
                ]
            },
            policies: [
                IPA.service.certificate_policy
            ]
        },
        {
            $type: 'association',
            name: 'managedby_host',
            add_method: 'add_host',
            remove_method: 'remove_host'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        $factory: IPA.service_adder_dialog,
        height: 350,
        sections: [
            {
                fields: [
                    {
                        $type: 'combobox',
                        name: 'service',
                        label: '@i18n:objects.service.service',
                        options: [
                            'cifs',
                            'DNS',
                            'ftp',
                            'HTTP',
                            'imap',
                            'ldap',
                            'libvirt',
                            'nfs',
                            'smtp',
                            'qpidd'
                        ],
                        editable: true,
                        size: 10,
                        required: true,
                        z_index: 2
                    },
                    {
                        $type: 'entity_select',
                        name: 'host',
                        other_entity: 'host',
                        other_field: 'fqdn',
                        label: '@i18n:objects.service.host',
                        required: true,
                        z_index: 1
                    },
                    {
                        $type: 'checkbox',
                        name: 'force',
                        metadata: '@mc-opt:service_add:force'
                    }
                ]
            }
        ]
    }
};};

IPA.service.details_facet = function(spec, no_init) {

    var that = IPA.details_facet(spec, true);
    that.certificate_loaded = IPA.observer();
    that.certificate_updated = IPA.observer();

    if (!no_init) that.init_details_facet();

    return that;
};

IPA.service_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entity_adder_dialog(spec);

    var init = function() {

        //small hack - krbprincipalname should not be displayed. This way
        //creation of associated widget is skipped.
        //In future it would be better split section definion into widget and
        //fields definition and create custom field with two associated
        //widgets - 'service' and 'host' with this dialog's save logic.
        that.builder.build_field({
            $type: 'field',
            name: 'krbprincipalname',
            required: false
        });
    };

    that.save = function(record) {

        var field = that.fields.get_field('service');
        var service = field.save()[0];

        field = that.fields.get_field('host');
        var host = field.save()[0];

        record['krbprincipalname'] = [ service+'/'+host ];

        field = that.fields.get_field('force');
        record['force'] = field.save();
    };

    init();

    return that;
};

IPA.service_name_adapter = declare([field_mod.Adapter], {
    load: function(data) {
        var record = this.get_record(data);
        var krbprincipalname = record.krbprincipalname[0];
        var value = krbprincipalname.replace(/\/.*$/, '');
        return [value];
    }
});

IPA.service_host_adapter = declare([field_mod.Adapter], {
    load: function(data) {
        var record = this.get_record(data);
        var krbprincipalname = record.krbprincipalname[0];
        var value = krbprincipalname.replace(/^.*\//, '').replace(/@.*$/, '');
        return [value];
    }
});

IPA.service_provisioning_status_widget = function (spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        that.status_valid = $('<div/>', {
            name: 'kerberos-key-valid',
            'class': 'provisioning-status',
            style: 'display: none;'
        }).appendTo(container);

        var content = $('<label/>', {
        }).appendTo(that.status_valid);

        $('<i/>', {
            'class': 'fa fa-check'
        }).appendTo(content);
        content.append(' ');
        content.append(text.get('@i18n:objects.service.valid'));

        that.status_missing = $('<div/>', {
            name: 'kerberos-key-missing',
            'class': 'provisioning-status',
            style: 'display: none;'
        }).appendTo(container);

        content = $('<label/>', {
        }).appendTo(that.status_missing);

        $('<i/>', {
            'class': 'fa fa-warning'
        }).appendTo(content);
        content.append(' ');
        content.append(text.get('@i18n:objects.service.missing'));
    };

    that.update = function(values) {
        that.status = values && values.length ? values[0] : false;
        set_status(that.status ? 'valid' : 'missing');
        that.on_value_changed(values);
    };

    that.clear = function() {
        that.status_valid.css('display', 'none');
        that.status_missing.css('display', 'none');
    };

    function set_status(status) {
        that.status_valid.css('display', status == 'valid' ? 'inline' : 'none');
        that.status_missing.css('display', status == 'missing' ? 'inline' : 'none');
    }

    return that;
};

IPA.service.unprovision_dialog = function(spec) {

    spec = spec || {};
    spec.title = spec.title || '@i18n:objects.service.unprovision_title';

    var that = IPA.dialog(spec);
    that.facet = spec.facet;

    var entity_singular = that.entity.metadata.label_singular;
    that.title = that.title.replace('${entity}', entity_singular);

    that.create_content = function() {
        that.container.append(text.get('@i18n:objects.service.unprovision_confirmation'));
    };

    that.create_buttons = function() {

        that.create_button({
            name: 'unprovision',
            label: '@i18n:objects.service.unprovision',
            click: function() {
                that.unprovision();
            }
        });

        that.create_button({
            name: 'cancel',
            label: '@i18n:buttons.cancel',
            click: function() {
                that.close();
            }
        });
    };

    that.unprovision = function() {

        var principal_f  = that.facet.fields.get_field('krbprincipalname');
        var pkey = principal_f.get_value()[0];

        rpc.command({
            entity: that.entity.name,
            method: 'disable',
            args: [pkey],
            on_success: function(data, text_status, xhr) {
                that.facet.refresh();
                that.close();
                IPA.notify_success('@i18n:objects.service.unprovisioned');
            },
            on_error: function(xhr, text_status, error_thrown) {
                that.close();
            }
        }).execute();
    };

    that.create_buttons();

    return that;
};

IPA.service.unprovision_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'unprovision';
    spec.label = spec.label || '@i18n:objects.service.delete_key_unprovision';
    spec.enable_cond = spec.enable_cond || ['has_keytab', 'krbprincipalkey_w'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        var dialog = IPA.service.unprovision_dialog({
            entity: facet.entity,
            facet: facet
        });

        dialog.open();
    };

    return that;
};

IPA.service.krbprincipalkey_acl_evaluator = function(spec) {

    spec.name = spec.name || 'unprovision_acl_evaluator';
    spec.attribute = spec.attribute || 'krbprincipalkey';

    var that = IPA.acl_state_evaluator(spec);
    return that;
};

IPA.service.has_keytab_evaluator = function(spec) {

    spec.name = spec.name || 'has_keytab_evaluator';
    spec.attribute = spec.attribute || 'has_keytab';
    spec.value = spec.value || [true];
    spec.representation = spec.representation || 'has_keytab';

    var that = IPA.value_state_evaluator(spec);
    return that;
};

IPA.service.certificate_policy = function(spec) {

    spec = spec || {};

    function get_pkey(result) {
        var values = result.krbprincipalname;
        return values ? values[0] : null;
    }

    spec.get_pkey = spec.get_pkey || get_pkey;

    spec.get_name = spec.get_name || function(result) {
        var value = get_pkey(result);
        return value ? value.replace(/@.*$/, '') : null;
    };

    spec.get_principal = spec.get_principal || get_pkey;

    spec.get_cn = spec.get_cn || function(result) {
        var value = get_pkey(result);
        if (value) {
            value = value.replace(/@.*$/, '').replace(/^.*\//, '');
        }
        return value;
    };

    spec.get_cn_name = spec.get_cn_name || function(result) {
        return "hostname";
    };

    var that = IPA.cert.load_policy(spec);
    return that;
};

exp.entity_spec = make_spec();
phases.on('registration', function() {
    var e = reg.entity;
    var w = reg.widget;
    var f = reg.field;
    var a = reg.action;

    e.register({type: 'service', spec: exp.entity_spec});

    f.register('service_provisioning_status', IPA.field);
    w.register('service_provisioning_status', IPA.service_provisioning_status_widget);
    a.register('service_unprovision', IPA.service.unprovision_action);
});


return exp;
});
