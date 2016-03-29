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
        'dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/_base/array',
        'dojo/Deferred',
        'dojo/on',
        'dojo/topic',
        'dojo/query',
        'dojo/dom-class',
        './auth',
        './json2',
        './widgets/App',
        './widgets/FacetContainer',
        './ipa',
        './reg',
        './navigation/Menu',
        './navigation/Router',
        './navigation/routing',
        './navigation/menu_spec',
        './plugins/load_page'
       ],
       function(declare, lang, array, Deferred, on, topic, query, dom_class, auth,
            JSON, App_widget, FacetContainer, IPA, reg, Menu, Router, routing, menu_spec) {

    /**
     * Application controller
     *
     * Controls interaction between navigation, menu and facets.
     *
     * @class Application_controller
     */
    var App = declare(null, {

        /**
         * Facet container map
         */
        containers: null,

        app_widget: null,

        router: null,

        menu: null,

        initialized: false,

        facet_changing: false,

        /**
         * Currently displayed facet
         *
         */
        current_facet: null,

        /**
         * Currently displayed facet container
         */
        current_container: null,

        init: function() {
            this.menu = new Menu();
            this.router = new Router();
            routing.init(this.router);

            var body_node = query('body')[0];
            this.app_widget = new App_widget();
            this.app_widget.container_node = body_node;
            this.app_widget.menu_widget.set_menu(this.menu);

            var simple_container = new FacetContainer();
            simple_container.container_node = body_node;

            var notification_container = new FacetContainer({
                container_node: body_node,
                id: "notification",
                'class': ''
            });

            this.containers = {
                // Default view
                main: {
                    widget: this.app_widget
                },
                // Mainly for standalone facets
                simple: {
                    widget: simple_container
                }
            };

            on(this.app_widget.menu_widget, 'item-select', lang.hitch(this, this.on_menu_click));
            on(this.app_widget, 'profile-click', lang.hitch(this, this.on_profile));
            on(this.app_widget, 'logout-click', lang.hitch(this, this.on_logout));
            on(this.app_widget, 'password-reset-click', lang.hitch(this, this.on_password_reset));
            on(this.app_widget, 'about-click', lang.hitch(this, this.on_about));

            on(this.router, 'facet-show', lang.hitch(this, this.on_facet_show));
            on(this.router, 'facet-change', lang.hitch(this, this.on_facet_change));
            on(this.router, 'facet-change-canceled', lang.hitch(this, this.on_facet_canceled));
            on(this.router, 'error', lang.hitch(this, this.on_router_error));
            topic.subscribe('phase-error', lang.hitch(this, this.on_phase_error));
            topic.subscribe('authenticate', lang.hitch(this, this.on_authenticate));

            this.app_widget.render();
            this.app_widget.hide();
            simple_container.render();
            simple_container.hide();
            notification_container.render();
            var load_facet = reg.facet.get('load');
            this.show_facet(load_facet);
            IPA.opened_dialogs.start_handling(this);
        },

        /**
         * Gets:
         *  * metadata
         *  * server configuration
         *  * user information
         */
        get_configuration: function(success_handler, error_handler) {
            IPA.init({ on_success: success_handler, on_error: error_handler});
        },

        /**
         * Deduces current application profile - administraion or self-service.
         * Initializes profiles's menu.
         */
        choose_profile: function() {

            // TODO: change IPA.whoami.cn[0] to something readable
            this.update_logged_in(true, IPA.whoami.cn[0]);
            var selfservice = this.is_selfservice();


            this.app_widget.menu_widget.ignore_changes = true;

            if (selfservice) {
                this.menu.name = menu_spec.self_service.name;
                this.menu.add_items(menu_spec.self_service.items);
            } else {
                this.menu.name = menu_spec.admin.name;
                this.menu.add_items(menu_spec.admin.items);
            }

            this.app_widget.menu_widget.ignore_changes = false;
            this.app_widget.menu_widget.render();
            this.app_widget.menu_widget.select(this.menu.selected);
        },

        start_runtime: function() {
            this.run_time = new Deferred();

            // hide load or login facets
            this.hide_facet();

            IPA.update_password_expiration();


            // now we are ready for displaying a facet,
            // it can match a facet if hash is set
            this.router.startup();

            // choose default facet if not defined by route
            if (!this.current_facet) {
                this.navigate_to_default();
            }

            return this.run_time.promise;
        },

        navigate_to_default: function() {
            if (IPA.is_selfservice) {
                this.on_profile();
            } else {
                routing.navigate(routing.default_path);
            }
        },

        start_logout: function() {
            IPA.logout();
        },

        is_selfservice: function() {
            var whoami = IPA.whoami;
            var self_service = true;


            if (whoami.hasOwnProperty('memberof_group') &&
                whoami.memberof_group.indexOf('admins') !== -1) {
                self_service = false;
            } else if (whoami.hasOwnProperty('memberofindirect_group')&&
                    whoami.memberofindirect_group.indexOf('admins') !== -1) {
                self_service = false;
            } else if (whoami.hasOwnProperty('memberof_role') &&
                    whoami.memberof_role.length > 0) {
                self_service = false;
            } else if (whoami.hasOwnProperty('memberofindirect_role') &&
                    whoami.memberofindirect_role.length > 0) {
                self_service = false;
            }

            IPA.is_selfservice = self_service; // quite ugly, needed for users

            return self_service;
        },

        update_logged_in: function(logged_in, fullname) {
            this.app_widget.set('logged', logged_in);
            this.app_widget.set('fullname', fullname);
        },

        on_profile: function() {
            routing.navigate(['entity', 'user', 'details', [IPA.whoami.uid[0]]]);
        },

        on_logout: function(event) {
            this.run_time.resolve();
        },

        on_password_reset: function() {
            IPA.password_selfservice();
        },

        on_about: function() {
            var dialog = IPA.about_dialog();
            dialog.open();
        },

        on_phase_error: function(error) {

            error = error || {};
            var name = error.name || 'Runtime error';
            var error_container = $('<div/>', {
                'class': 'container facet-content facet-error'
            }).appendTo($('.app-container .content').empty());
            error_container.append($('<h1/>', { text: name }));
            var details = $('<div/>', {
                'class': 'error-details'
            }).appendTo(error_container);

            details.append($('<p/>', { text: 'Web UI got in unrecoverable state during "' + error.phase + '" phase' }));
            if (error.name) window.console.error(error.name);
            if (error.results) {
                var msg = error.results.message;
                var stack = error.results.stack.toString();
                window.console.error(stack);
                details.append('<h3>Technical details:</h3>');
                details.append($('<div/>', { text: error.results.message }));
                details.append($('<div/>').append($('<code/>', { text: stack })));
            }
        },

        on_facet_change: function(event) {
            //this.facet_changing =  true;
            var new_facet = event.facet;
            var current_facet = this.current_facet;

            if (current_facet === new_facet) return;

            if (current_facet && !current_facet.can_leave()) {
                var permit_clb = lang.hitch(this, function() {
                    // Some facet's might not call reset before this call but after
                    // so they are still dirty. Calling reset prevent's opening of
                    // dirty dialog again.
                    if (current_facet.is_dirty()) current_facet.reset(); //TODO change
                    this.router.navigate_to_hash(event.hash, event.facet);
                });

                var dialog = current_facet.show_leave_dialog(permit_clb);
                this.router.canceled = true;
                dialog.open();
            }
        },

        on_facet_canceled: function(event) {
        },

        on_facet_state_changed: function(event) {
            if (event.facet === this.current_facet) {
                routing.update_hash(event.facet, event.state);
            }
        },

        on_facet_show: function(event) {
            this.show_facet(event.facet);
        },

        show_facet: function(facet) {

            // prevent changing facet when authenticating
            if (this.current_facet && this.current_facet.name === 'login' &&
                !auth.current.authenticated && facet.requires_auth) {
                return;
            }

            // choose container
            var container = this.containers[facet.preferred_container];
            if (!container) container = this.containers.main;

            if (this.current_container !== container) {

                if (this.current_container) {
                    this.current_container.widget.hide();
                }

                this.current_container = container;
                this.current_container.widget.show();
            }

            // update menu
            var menu_item = this._find_menu_item(facet);
            if (menu_item) this.menu.select(menu_item);

            // show facet
            if (!facet.container_node) {
                facet.container_node = container.widget.content_node;
                on(facet, 'facet-state-change', lang.hitch(this, this.on_facet_state_changed));
            }

            if (this.current_facet !== facet) {
                IPA.opened_dialogs.hide();
            }

            this.hide_facet();
            this.current_facet = facet;
            facet.show();
            IPA.opened_dialogs.focus_top();
        },

        hide_facet: function() {

            if (this.current_facet) {
                this.current_facet.hide();
            }
            this.current_facet = null;
        },


        _find_menu_item: function(facet) {

            var items = [];

            // entity facets
            if (facet.entity) {
                items = this.menu.query({ entity: facet.entity.name, facet: facet.name });
            }

            // entity fallback
            if (!items.total && facet.entity) {
                items = this.menu.query({ entity: facet.entity.name });
            }

            // normal facets
            if (!items.total) {
                items = this.menu.query({ facet: facet.name });
            }

            // fallback: Top level item
            if (!items.total) {
                items = this.menu.query({ parent: null });
            }

            if (items.total) {
                if (items.total === 1) return items[0];

                // select the menu item with the most similar state as the facet
                var best = items[0];
                var best_score = 0;
                var item, i, j, l, score;
                var state = facet.state;
                for (i=0, l=items.total; i<l; i++) {
                    item = items[i];
                    score = 0;
                    if (item.pkeys && facet.get_pkeys) {
                        var pkeys = facet.get_pkeys();
                        for (j=0, j=item.pkeys.length; j<l; j++) {
                            if (pkeys.indexOf(item.pkeys[j]) > -1) score++;
                        }
                    }
                    if (item.args) {
                        for (var name in item.args) {
                            if (!item.args.hasOwnProperty(name)) continue;
                            if (state[name] == item.args[name]) score++;
                        }
                    }
                    if (score > best_score) {
                        best_score = score;
                        best = item;
                    }
                }

                return best;
            }
        },

        on_router_error: function(error) {

            if (error.type === 'route') {
                this.navigate_to_default();
            }
        },

        /**
         * Tries to find menu item with assigned facet and navigate to it.
         */
        on_menu_click: function(menu_item) {
            this._navigate_to_menu_item(menu_item);
        },

        _navigate_to_menu_item: function(menu_item) {

            if (menu_item.entity) {
                // entity pages
                routing.navigate([
                    'entity',
                    menu_item.entity,
                    menu_item.facet,
                    menu_item.pkeys,
                    menu_item.args]);
            } else if (menu_item.facet) {
                // concrete facets
                routing.navigate(['generic', menu_item.facet, menu_item.args]);
            } else {
                // categories, select first posible child, it may be the last
                var children = this.menu.query({parent: menu_item.name });
                if (children.total) {
                    var success = false;
                    for (var i=0; i<children.total;i++) {
                        success = this._navigate_to_menu_item(children[i]);
                        if (success) break;
                    }
                } else {
                    return false;
                }
            }

            return true;
        },

        /**
         * Starts authentication process in authentication UI
         * @returns {undefined}
         */
        on_authenticate: function() {

            var self = this;
            if (this.auth_ui === 'dialog') {
                var dummy_command = {
                    execute: function() {
                        topic.publish('auth-successful');
                    }
                };

                var dialog = IPA.unauthorized_dialog({
                    close_on_escape: false,
                    error_thrown: { name: '', message: ''},
                    command: dummy_command
                });

                dialog.open();
            } else {
                var facet = this.current_facet;

                // we don't want the load facet to be displayed after successful auth
                if (facet && facet.name === 'load') {
                    facet = null;
                }
                var login_facet = reg.facet.get('login');

                on.once(login_facet, "logged_in", function() {
                    if (facet) {
                        self.show_facet(facet);
                    }
                    topic.publish('auth-successful');
                });
                this.show_facet(login_facet);
            }
        }
    });

    return App;
});