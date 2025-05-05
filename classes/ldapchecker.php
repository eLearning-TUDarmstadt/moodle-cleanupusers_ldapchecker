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
 * Sub-plugin ldapchecker.
 *
 * @package   userstatus_ldapchecker
 * @copyright 2016/17 N. Herrmann
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace userstatus_ldapchecker;

use tool_cleanupusers\archiveduser;
use tool_cleanupusers\userstatusinterface;

/**
 * Class that checks the status of different users depending on the time they have not signed in for.
 *
 * @package    userstatus_ldapchecker
 * @copyright  2016/17 N Herrmann
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

class ldapchecker implements userstatusinterface {
    /** @var int seconds until a user should be deleted */
    private $timedelete;

    /** @var array lookuptable for ldap users */
    private $lookup = [];

    /** @var string id of authentication method */
    private $authtype;

    /**
     * This constructor sets timesuspend and timedelete from days to seconds.
     * @throws \dml_exception
     */
    public function __construct($testing = false) {

        $config = get_config('userstatus_ldapchecker');

        // Calculates days to seconds.
        $this->timedelete = $config->deletetime * 86400;
        $this->authtype = $config->authtype;

        // Only connect to LDAP if we are not in testing case.
        if ($testing === false) {
            $ldap = ldap_connect($config->host_url);
            if (!$ldap) {
                die("Could not connect to $config->host_url");
            }
            ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, $config->ldap_version);
            $bind = ldap_bind($ldap, $config->bind_dn, $config->bind_pw); // Returns 1 if correct.

            if ($bind) {
                $this->log("ldap_bind successful");

                $contexts = $config->contexts;

                $attributes = ['cn'];
                $filter = '(cn=*)';
                $search = ldap_search($ldap, $contexts, $filter, $attributes);
                if (!$search) {
                    die("Error in search Query: " . ldap_error($ldap));
                }
                $result = ldap_get_entries($ldap, $search);

                foreach ($result as $user) {
                    if (isset($user['cn'])) {
                        foreach ($user['cn'] as $cn) {
                            $this->lookup[$cn] = true;
                        }
                    }
                }

                $this->log("ldap server sent " . count($this->lookup) . " users");
            } else {
                // Abort on failure of ldap binding
                die("ldap_bind failed");
            }
        }
    }

    private function log($text) {
        file_put_contents(
            "/var/log/httpd/debug_log_ldapchecker.log",
            "\n[" . date("d-M-Y - H:i ") . "] $text ",
            FILE_APPEND
        );
    }

    /**
     * All users who are not suspended and not deleted are selected. If a user did not sign in for the hitherto
     * determined suspendtime he/she will be returned.
     * Users not signed in for the hitherto determined suspendtime, do not show up in the ldap lookuptable.
     * The array includes merely the necessary information which comprises the userid, lastaccess, suspended, deleted
     * and the username.
     *
     * @return array of users to suspend
     * @throws \dml_exception
     */
    public function get_to_suspend() {
        global $DB;

        $params['authtype'] = $this->authtype;

        $users = $DB->get_records_sql(
            "SELECT id, suspended, lastaccess, username, deleted
                FROM {user}
                WHERE auth = :authtype
                    AND suspended = 0
                    AND deleted = 0",
            $params
        );

        $tosuspend = [];
        foreach ($users as $key => $user) {
            if (!is_siteadmin($user) && !array_key_exists($user->username, $this->lookup)) {
                $suspenduser = new archiveduser(
                    $user->id,
                    $user->suspended,
                    $user->lastaccess,
                    $user->username,
                    $user->deleted
                );
                $tosuspend[$key] = $suspenduser;
                $this->log("[get_to_suspend] " . $user->username . " marked");
            }
        }
        $this->log("[get_to_suspend] marked " . count($tosuspend) . " users");

        return $tosuspend;
    }

    /**
     * All users who never logged in will be returned in the array.
     * The array includes merely the necessary information which comprises the userid, lastaccess, suspended, deleted
     * and the username.
     *
     * @return array of users who never logged in
     * @throws \dml_exception
     */
    public function get_never_logged_in() {
        global $DB;

        $params['authtype'] = $this->authtype;

        $arrayofuser = $DB->get_records_sql(
            "SELECT u.id, u.suspended, u.lastaccess, u.username, u.deleted
                FROM {user} u
                LEFT JOIN {tool_cleanupusers} tc ON u.id = tc.id
                WHERE u.auth = :authtype
                    AND u.lastaccess = 0
                    AND u.deleted = 0
                    AND tc.id IS NULL",
            $params
        );

        $neverloggedin = [];
        foreach ($arrayofuser as $key => $user) {
            $informationuser = new archiveduser(
                $user->id,
                $user->suspended,
                $user->lastaccess,
                $user->username,
                $user->deleted
            );
            $neverloggedin[$key] = $informationuser;
        }

        return $neverloggedin;
    }

    /**
     * All users who should be deleted will be returned in the array.
     * The array includes merely the necessary information which comprises the userid, lastaccess, suspended, deleted
     * and the username.
     * The function checks the user table and the tool_cleanupusers_archive table. Therefore, users who are suspended by
     * the tool_cleanupusers plugin and users who are suspended manually are screened.
     *
     * @return array of users who should be deleted.
     * @throws \dml_exception
     */
    public function get_to_delete() {
        global $DB;

        $params['authtype'] = $this->authtype;
        $params['timelimit'] = time() - $this->timedelete;

        $users = $DB->get_records_sql(
            "SELECT tca.id, tca.suspended, tca.lastaccess, tca.username, tca.deleted
                FROM {user} u
                JOIN {tool_cleanupusers} tc ON u.id = tc.id
                JOIN {tool_cleanupusers_archive} tca ON u.id = tca.id
                WHERE u.auth = :authtype
                    AND u.suspended = 1
                    AND u.deleted = 0
                    AND tc.timestamp < :timelimit",
            $params
        );

        $todelete = [];
        foreach ($users as $key => $user) {
            if (!is_siteadmin($user) && !array_key_exists($user->username, $this->lookup)) {
                $deleteuser = new archiveduser(
                    $user->id,
                    $user->suspended,
                    $user->lastaccess,
                    $user->username,
                    $user->deleted
                );
                $todelete[$key] = $deleteuser;
                $this->log("[get_to_delete] " . $user->username . " marked");
            }
        }
        $this->log("[get_to_delete] marked " . count($todelete) . " users");

        return $todelete;
    }

    /**
     * All users that should be reactivated will be returned.
     *
     * @return array of objects
     * @throws \dml_exception
     * @throws \dml_exception
     */
    public function get_to_reactivate() {
        global $DB;

        $params['authtype'] = $this->authtype;

        $users = $DB->get_records_sql(
            "SELECT tca.id, tca.suspended, tca.lastaccess, tca.username, tca.deleted
                FROM {user} u
                JOIN {tool_cleanupusers} tc ON u.id = tc.id
                JOIN {tool_cleanupusers_archive} tca ON u.id = tca.id
                WHERE u.auth = :authtype
                    AND u.suspended = 1
                    AND u.deleted = 0
                    AND tca.username NOT IN
                        (SELECT username FROM {user} WHERE username IS NOT NULL)",
            $params
        );

        $toactivate = [];
        foreach ($users as $key => $user) {
            if (!is_siteadmin($user) && array_key_exists($user->username, $this->lookup)) {
                $activateuser = new archiveduser(
                    $user->id,
                    $user->suspended,
                    $user->lastaccess,
                    $user->username,
                    $user->deleted
                );
                $toactivate[$key] = $activateuser;
                $this->log("[get_to_reactivate] " . $user->username . " marked");
            }
        }
        $this->log("[get_to_reactivate] marked " . count($toactivate) . " users");

        return $toactivate;
    }

    public function fill_ldap_response_for_testing($dummyldap) {
        $this->lookup = $dummyldap;
    }
}
