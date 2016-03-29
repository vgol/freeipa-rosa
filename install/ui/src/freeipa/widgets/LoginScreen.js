/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
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

define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/dom-construct',
        'dojo/dom-style',
        'dojo/query',
        'dojo/on',
        '../ipa',
        '../auth',
        '../reg',
        '../FieldBinder',
        '../text',
        '../util',
        './LoginScreenBase'
       ],
       function(declare, lang,  construct, dom_style, query, on,
                IPA, auth, reg, FieldBinder, text, util, LoginScreenBase) {


    /**
     * Widget with login form.
     *
     * Supported operations:
     *
     * - login with password, kerberos
     * - password change
     *
     * @class widgets.LoginScreen
     */
    var LoginScreen = declare([LoginScreenBase], {

        expired_msg: "Your session has expired. Please re-login.",

        form_auth_msg: "<i class=\"fa fa-info-circle\"></i> To login with <strong>username and password</strong>, enter them in the corresponding fields, then click Login.",

        kerberos_msg: "<i class=\"fa fa-info-circle\"></i> To login with <strong>Kerberos</strong>, please make sure you" +
                    " have valid tickets (obtainable via kinit) and " +
                    "<a href='http://${host}/ipa/config/unauthorized.html'>configured</a>" +
                    " the browser correctly, then click Login. ",

        form_auth_failed: "The password or username you entered is incorrect. ",

        krb_auth_failed: "Authentication with Kerberos failed",

        password_expired: "Your password has expired. Please enter a new password.",

        password_change_complete: "Password change complete",

        denied: "Sorry you are not allowed to access this service.",


        //nodes:
        login_btn_node: null,
        reset_btn_node: null,

        /**
         * View this form is in.
         *
         * Possible views: ['login', 'reset']
         * @property {string}
         */
        view: 'login',

        render_buttons: function(container) {

            this.sync_btn_node = IPA.button({
                name: 'sync',
                label: text.get('@i18n:login.sync_otp_token', "Sync OTP Token"),
                button_class: 'btn btn-link',
                click: lang.hitch(this, this.on_sync)
            })[0];
            construct.place(this.sync_btn_node, container);
            construct.place(document.createTextNode(" "), container);

            this.login_btn_node = IPA.button({
                name: 'login',
                label: text.get('@i18n:login.login', "Login"),
                'class': 'btn-primary btn-lg',
                click: lang.hitch(this, this.on_confirm)
            })[0];
            construct.place(this.login_btn_node, container);
            construct.place(document.createTextNode(" "), container);

            this.cancel_btn_node = IPA.button({
                name: 'cancel',
                label: text.get('@i18n:buttons.cancel', "Cancel"),
                'class': 'btn-default',
                click: lang.hitch(this, this.on_cancel)
            })[0];
            construct.place(this.cancel_btn_node, container);
            construct.place(document.createTextNode(" "), container);

            this.reset_btn_node = IPA.button({
                name: 'reset',
                label: text.get('@i18n:buttons.reset_password', "Reset Password"),
                'class': 'btn-primary btn-lg',
                click: lang.hitch(this, this.on_confirm)
            })[0];
            construct.place(this.reset_btn_node, container);
            construct.place(document.createTextNode(" "), container);

            this.reset_and_login_btn_node = IPA.button({
                name: 'reset_and_login',
                label: text.get('@i18n:buttons.reset_password_and_login', "Reset Password and Login"),
                'class': 'btn-primary btn-lg',
                click: lang.hitch(this, this.on_confirm)
            })[0];
            construct.place(this.reset_and_login_btn_node, container);
        },

        set_visible_buttons: function(buttons) {
            if (!this.buttons_node) return;
            query('button', this.buttons_node).forEach(function(el) {
                if (buttons.indexOf(el.name) > -1) {
                    dom_style.set(el, 'display', '');
                } else {
                    dom_style.set(el, 'display', 'none');
                }
            });
        },

        post_create_fields: function() {
            var u_f = this.get_field('username');
            var p_f = this.get_field('password');
            var otp_f = this.get_field('otp');

            u_f.on('value-change', lang.hitch(this, this.on_form_change));
            p_f.on('value-change', lang.hitch(this, this.on_form_change));
            otp_f.on('value-change', lang.hitch(this, this.on_otp_change));
            this.on_form_change();
        },

        on_form_change: function(event) {

            var u_f = this.get_field('username');
            var p_f = this.get_field('password');
            var required = !util.is_empty(u_f.get_value()) ||
                    !util.is_empty(p_f.get_value()) || !this.kerberos_enabled();
            u_f.set_required(required);
            p_f.set_required(required);
        },

        on_otp_change: function(event) {
            if (this.view === 'login') return;
            if (!event.value[0]) {
                this.set_visible_buttons(['cancel', 'reset_and_login']);
            } else {
                this.set_visible_buttons(['cancel', 'reset']);
            }
        },

        on_sync: function() {
            var user = this.get_field('username').get_value()[0];
            this.get_widget('validation').remove_all('error');
            this.emit('require-otp-sync', { source: this, user: user });
        },

        on_confirm: function() {
            if (this.view == 'login') {
                this.login();
            } else {
                this.login_and_reset();
            }
        },

        on_cancel: function() {
            this.set('view', 'login');
        },

        login: function() {

            var val_summary = this.get_widget('validation');
            val_summary.remove('login');

            if (!this.validate()) return;

            var login = this.get_field('username').get_value()[0];
            if (util.is_empty(login) && this.kerberos_enabled()) {
                this.login_with_kerberos();
            } else {
                this.login_with_password();
            }
        },

        login_with_kerberos: function() {

            IPA.get_credentials().then(lang.hitch(this, function(status) {
                if (status === 200) {
                    this.emit('logged_in');
                } else {
                    var val_summary = this.get_widget('validation');
                    val_summary.add_error('login', this.krb_auth_failed);
                }
            }));
        },

        login_with_password: function() {

            if(!this.password_enabled()) return;

            var val_summary = this.get_widget('validation');
            var login = this.get_field('username').get_value()[0];
            var password_f = this.get_field('password');
            var password = password_f.get_value()[0];

            IPA.login_password(login, password).then(
                lang.hitch(this, function(result) {

                if (result === 'success') {
                    this.emit('logged_in');
                    password_f.set_value('');
                } else if (result === 'password-expired') {
                    this.set('view', 'reset');
                    val_summary.add_info('login', this.password_expired);
                } else {
                    val_summary.add_error('login', this.form_auth_failed);
                    password_f.set_value('');
                }
            }));
        },

        login_and_reset: function() {

            var val_summary = this.get_widget('validation');
            val_summary.remove('login');

            if (!this.validate()) return;

            var psw_f = this.get_field('password');
            var psw_f2 = this.get_field('current_password');
            var otp_f = this.get_field('otp');
            var new_f = this.get_field('new_password');
            var ver_f = this.get_field('verify_password');
            var username_f = this.get_field('username');

            var psw = psw_f2.get_value()[0] || psw_f.get_value()[0];
            var otp = otp_f.get_value()[0];

            var result = IPA.reset_password(
                username_f.get_value()[0],
                psw,
                new_f.get_value()[0],
                otp);

            if (result.status === 'ok') {
                val_summary.add_success('login', this.password_change_complete);
                psw_f.set_value('');
                psw_f2.set_value('');
                // do not login if otp is used because it will fail (reuse of OTP)
                if (!otp) {
                    psw_f.set_value(new_f.get_value());
                    this.login();
                }
                this.set('view', 'login');
            } else {
                val_summary.add_error('login', result.message);
            }

            otp_f.set_value('');
            new_f.set_value('');
            ver_f.set_value('');
        },

        refresh: function() {
            if (this.view === 'reset') {
                this.show_reset_view();
            } else {
                this.show_login_view();
            }
        },

        show_login_view: function() {
            this.set_login_aside_text();
            if (auth.current.expired) {
                var val_summary = this.get_widget('validation');
                val_summary.add_info('expired', this.expired_msg);
            }
            this.set_visible_buttons(['sync', 'login']);
            if (this.password_enabled()) {
                this.use_fields(['username', 'password']);
                var username_f = this.get_field('username');
                if (username_f.get_value()[0]) {
                    this.get_widget('password').focus_input();
                } else {
                    this.get_widget('username').focus_input();
                }
            } else {
                this.use_fields([]);
                this.login_btn_node.focus();
            }
        },

        show_reset_view: function() {

            this.set_reset_aside_text();
            this.set_visible_buttons(['cancel', 'reset_and_login']);
            this.use_fields(['username_r', 'current_password', 'otp', 'new_password', 'verify_password']);

            var val_summary = this.get_widget('validation');

            var u_f = this.fields.get('username');
            var u_r_f = this.fields.get('username_r');
            u_r_f.set_value(u_f.get_value());
            this.get_widget('current_password').focus_input();
        },

        set_login_aside_text: function() {
            var aside = "";
            if (this.password_enabled()) {
                aside += "<p>"+this.form_auth_msg;+"<p/>";
            }
            if (this.kerberos_enabled()) {
                aside += "<p>"+this.kerberos_msg;+"<p/>";
            }
            this.set('aside', aside);
        },

        set_reset_aside_text: function() {
            this.set('aside', "<p>"+this.otp_info_msg+"<p/>");
        },

        constructor: function(spec) {
            spec = spec || {};

            this.expired_msg = text.get(spec.expired_msg || '@i18n:ajax.401.message',
                this.expired_msg);

            this.form_auth_msg = text.get(spec.form_auth_msg || '@i18n:login.form_auth',
                this.form_auth_msg);

            this.kerberos_msg = text.get(spec.kerberos_msg || '@i18n:login.krb_auth_msg',
                this.kerberos_msg);

            this.kerberos_msg = this.kerberos_msg.replace('${host}', window.location.hostname);

            this.password_change_complete = text.get(spec.password_change_complete ||
                '@i18n:password.password_change_complete', this.password_change_complete);

            this.krb_auth_failed = text.get(spec.krb_auth_failed, this.krb_auth_failed);

            this.field_specs = LoginScreen.field_specs;
        }
    });

    LoginScreen.field_specs = [
        {
            $type: 'text',
            name: 'username',
            label: text.get('@i18n:login.username', "Username"),
            placeholder: text.get('@i18n:login.username', "Username"),
            show_errors: false,
            undo: false
        },
        {
            $type: 'password',
            name: 'password',
            label: text.get('@i18n:login.password', "Password"),
            placeholder: text.get('@i18n:login.password_and_otp', 'Password or Password+One-Time-Password'),
            show_errors: false,
            undo: false
        },
        {
            name: 'username_r',
            read_only: true,
            label: text.get('@i18n:login.username', "Username"),
            show_errors: false,
            undo: false
        },
        {
            name: 'current_password',
            $type: 'password',
            label: text.get('@i18n:login.current_password', "Current Password"),
            placeholder: text.get('@i18n:login.current_password', "Current Password"),
            show_errors: false,
            undo: false
        },
        {
            name: 'otp',
            $type: 'password',
            label: text.get('@i18n:password.otp', "OTP"),
            placeholder: text.get('@i18n:password.otp_long', 'One-Time-Password'),
            show_errors: false,
            undo: false
        },
        {
            name: 'new_password',
            $type: 'password',
            required: true,
            label: text.get('@i18n:password.new_password)', "New Password"),
            placeholder: text.get('@i18n:password.new_password)', "New Password"),
            show_errors: false,
            undo: false
        },
        {
            name: 'verify_password',
            $type: 'password',
            required: true,
            label: text.get('@i18n:password.verify_password', "Verify Password"),
            placeholder: text.get('@i18n:password.new_password)', "New Password"),
            validators: [{
                $type: 'same_password',
                other_field: 'new_password'
            }],
            show_errors: false,
            undo: false
        }
    ];

    return LoginScreen;
});