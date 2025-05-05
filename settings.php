<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Settings.php
 * @package userstatus_ldapchecker
 * @copyright 2016/17 N Herrmann
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

// Included in admin/tool/cleanupusers/classes/plugininfo/userstatus.php, therefore, need to include global variables.
global $CFG, $PAGE;

if ($hassiteconfig) {
    $url = $CFG->wwwroot . '/' . $CFG->admin . '/tool/cleanupusers/ldapchecker/index.php';


    $settings->add(new admin_setting_heading('ldapchecker_heading', get_string(
        'settingsinformation',
        'userstatus_ldapchecker'
    ), get_string('introsettingstext', 'userstatus_ldapchecker')));

    $settings->add(new admin_setting_configtext(
        'userstatus_ldapchecker/deletetime',
        get_string('deletetime', 'userstatus_timechecker'),
        get_string('timechecker_time_to_delete', 'userstatus_timechecker'),
        365,
        PARAM_INT
    ));

    // Get installed auth types for choices
    $plugins = core_plugin_manager::instance()->get_plugins_of_type('auth');
    $auths = [];
    foreach ($plugins as $plugin) {
        $auths[$plugin->name] = $plugin->displayname;
    }
    $settings->add(new admin_setting_configselect(
        'userstatus_ldapchecker/authtype',
        get_string('authtype', 'userstatus_ldapchecker'),
        get_string('authtype_desc', 'userstatus_ldapchecker'),
        null,
        $auths
    ));

    // LDAP server settings.
    $settings->add(new admin_setting_heading(
        'userstatus_ldapchecker/ldapserversettings',
        new lang_string('auth_ldap_server_settings', 'auth_ldap'),
        ''
    ));

    // Host.
    $settings->add(new admin_setting_configtext(
        'userstatus_ldapchecker/host_url',
        get_string('auth_ldap_host_url_key', 'auth_ldap'),
        get_string('auth_ldap_host_url', 'auth_ldap'),
        '',
        PARAM_RAW_TRIMMED
    ));

    // Version.
    $versions = [];
    $versions[2] = '2';
    $versions[3] = '3';
    $settings->add(new admin_setting_configselect(
        'userstatus_ldapchecker/ldap_version',
        new lang_string('auth_ldap_version_key', 'auth_ldap'),
        new lang_string('auth_ldap_version', 'auth_ldap'),
        3,
        $versions
    ));

    // Start TLS.
    $yesno = [
        new lang_string('no'),
        new lang_string('yes'),
    ];

    $settings->add(new admin_setting_configselect(
        'userstatus_ldapchecker/start_tls',
        new lang_string('start_tls_key', 'auth_ldap'),
        new lang_string('start_tls', 'auth_ldap'),
        0,
        $yesno
    ));


    // Bind settings.
    $settings->add(new admin_setting_heading(
        'userstatus_ldapchecker/ldapbindsettings',
        new lang_string('auth_ldap_bind_settings', 'auth_ldap'),
        ''
    ));

    // User ID.
    $settings->add(new admin_setting_configtext(
        'userstatus_ldapchecker/bind_dn',
        get_string('auth_ldap_bind_dn_key', 'auth_ldap'),
        get_string('auth_ldap_bind_dn', 'auth_ldap'),
        '',
        PARAM_RAW_TRIMMED
    ));

    // Password.
    $settings->add(new admin_setting_configpasswordunmask(
        'userstatus_ldapchecker/bind_pw',
        get_string('auth_ldap_bind_pw_key', 'auth_ldap'),
        get_string('auth_ldap_bind_pw', 'auth_ldap'),
        ''
    ));

    // Contexts.
    $settings->add(new auth_ldap_admin_setting_special_contexts_configtext(
        'userstatus_ldapchecker/contexts',
        get_string('auth_ldap_contexts_key', 'auth_ldap'),
        get_string('auth_ldap_contexts', 'auth_ldap'),
        '',
        PARAM_RAW_TRIMMED
    ));
}
