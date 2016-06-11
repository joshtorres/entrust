<?php namespace Zizaco\Entrust\Traits;

/**
 * This file is part of Entrust,
 * a role & permission management solution for Laravel.
 *
 * @license MIT
 * @package Zizaco\Entrust
 */

use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use InvalidArgumentException;
use Symfony\Component\Routing\Exception\InvalidParameterException;

trait EntrustUserTrait
{
    //Big block of caching functionality.
    public function cachedRoles()
    {
        $userPrimaryKey = $this->primaryKey;
        $cacheKey = 'entrust_roles_for_user_'.$this->$userPrimaryKey;
//        return $this->roles()->get();

//        return Cache::tags(Config::get('entrust.role_user_table'))->remember($cacheKey, Config::get('cache.ttl'), function () {
            return $this->roles()->get();
//        });
    }
    public function save(array $options = [])
    {   //both inserts and updates
        parent::save($options);
    }
    public function delete(array $options = [])
    {   //soft or hard
        parent::delete($options);
    }
    public function restore()
    {   //soft delete undo's
        parent::restore();
    }
    
    /**
     * Many-to-Many relations with Role
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function roles()
    {
        return $this->belongsToMany(Config::get('entrust.role'), Config::get('entrust.role_user_table'), Config::get('entrust.user_foreign_key'), Config::get('entrust.role_foreign_key'))
            ->withTimestamps();
    }

    /**
     * Return User's roles with Accounts and Modules info attached
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany $results
     */
    public function rolesFull()
    {
        $role_user_table = Config::get('entrust.role_user_table');
        $teams_table = Config::get('entrust.accounts_table');
        $modules_table = Config::get('entrust.modules_table');
        $roles_table = Config::get('entrust.roles_table');

        $results = $this->belongsToMany(Config::get('entrust.role'), $role_user_table, Config::get('entrust.user_foreign_key'), Config::get('entrust.role_foreign_key'))
            ->join($teams_table, $roles_table . '.' . Config::get('entrust.account_foreign_key'), '=', $teams_table . '.id')
            ->join($modules_table, $roles_table . '.'.Config::get('entrust.module_foreign_key'), '=', $modules_table . '.id')
            ->select(
                $teams_table .   '.id AS '         . rtrim($teams_table,'s')   . '_id' ,
//                $teams_table .   '.name AS '         . rtrim($teams_table,'s')   . '_name' ,
//                $teams_table .   '.team_slug AS ' . rtrim($teams_table,'s')   . '_slug' ,

                $modules_table .    '.id AS '           . rtrim($modules_table,'s')    . '_id',
//                $modules_table .    '.name AS '         . rtrim($modules_table,'s')    . '_name' ,
//                $modules_table .    '.module_slug AS '  . rtrim($modules_table,'s')    . '_slug' ,

                $roles_table .      '.*' /* AS '           . rtrim($roles_table,'s')      . '_id'*/
//                $roles_table .      '.name AS '         . rtrim($roles_table,'s')      . '_name' ,
//                $roles_table .      '.display_name AS ' . rtrim($roles_table,'s')      . '_display_name',
//                $roles_table .      '.description AS '  . rtrim($roles_table,'s')      . '_description',
//                $roles_table .      '.level AS '        . rtrim($roles_table,'s')      . '_level'
            )
            ->withTimestamps();

        return $results;
    }

    /**
     * Determine if user is Super Admin for a given account.
     * // @TODO [Josh] - this will be equivalent to isOwner for a team
     *
     * @param \App\Account $account defaults to \App\User->currentAccount()
     * @return bool
     */
    public function isSuperAdmin($account = null)
    {
        if ( is_null($account) ) {
            $account = $this->currentAccount();
        }
        return $this->hasRole('super_admin', $account);
    }

    /**
     * Check if User is a System Admin
     * You are a system admin if you are a Super Admin on Account 1, Module 1
     * // @TODO [Josh] - this will be equivalent to being in the "developers" array for spark
     *
     * @return bool
     */
    public function isSystemAdmin()
    {
        return $this->isSuperAdmin(1);
    }

    /**
     * Boot the user model
     * Attach event listener to remove the many-to-many records when trying to delete
     * Will NOT delete any records if the user model uses soft deletes.
     *
     * @return void|bool
     */
    public static function boot()
    {
        parent::boot();

        static::deleting(function($user) {
            if (!method_exists(Config::get('auth.model'), 'bootSoftDeletes')) {
                $user->roles()->sync([]);
            }

            return true;
        });
    }

    /**
     * Checks if the user has a role on a given account by its name.
     *
     * @param string|array $name Role name or array of role names.
     * @param \App\Team|array|int|null $team
     * @param bool $requireAll All roles in the array are required.
     * @return bool
     */
    public function hasRole($name, $team = null, $requireAll = false)
    {
        // this will require a joining of the user_role and roles table;
        // need to look up role ID, then look at user_role table and see if there is a row with user_id and role_id
        if ( is_null($team) ) {
            $team = $this->currentAccount();
        }
        $accountId = $this->_getId($team);

        if (is_array($name)) {
            foreach ($name as $roleName) {
                $hasRole = $this->hasRole($roleName, $accountId);

                if ($hasRole && !$requireAll) {
                    return true;
                } elseif (!$hasRole && $requireAll) {
                    return false;
                }
            }

            // If we've made it this far and $requireAll is FALSE, then NONE of the roles were found
            // If we've made it this far and $requireAll is TRUE, then ALL of the roles were found.
            // Return the value of $requireAll;
            return $requireAll;
        } else {
            foreach ($this->cachedRoles() as $role) {
                if ( ($role->account_id === $accountId) && ($role->name == $name) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if user has a permission by its name.
     *
     * @param string|array $permission Permission string or array of permissions.
     * @param bool         $requireAll All permissions in the array are required.
     *
     * @return bool
     */
    public function can($permission, $requireAll = false)
    {
        if (is_array($permission)) {
            foreach ($permission as $permName) {
                $hasPerm = $this->can($permName);

                if ($hasPerm && !$requireAll) {
                    return true;
                } elseif (!$hasPerm && $requireAll) {
                    return false;
                }
            }

            // If we've made it this far and $requireAll is FALSE, then NONE of the perms were found
            // If we've made it this far and $requireAll is TRUE, then ALL of the perms were found.
            // Return the value of $requireAll;
            return $requireAll;
        } else {
            foreach ($this->cachedRoles() as $role) {
                // Validate against the Permission table
                foreach ($role->cachedPermissions() as $perm) {
                    if (str_is( $permission, $perm->name) ) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Checks role(s) and permission(s).
     *
     * @param string|array $roles       Array of roles or comma separated string
     * @param string|array $permissions Array of permissions or comma separated string.
     * @param array        $options     validate_all (true|false) or return_type (boolean|array|both)
     *
     * @throws \InvalidArgumentException
     *
     * @return array|bool
     */
    public function ability($roles, $permissions, $options = [])
    {
        // Convert string to array if that's what is passed in.
        if (!is_array($roles)) {
            $roles = explode(',', $roles);
        }
        if (!is_array($permissions)) {
            $permissions = explode(',', $permissions);
        }

        // Set up default values and validate options.
        if (!isset($options['validate_all'])) {
            $options['validate_all'] = false;
        } else {
            if ($options['validate_all'] !== true && $options['validate_all'] !== false) {
                throw new InvalidArgumentException();
            }
        }
        if (!isset($options['return_type'])) {
            $options['return_type'] = 'boolean';
        } else {
            if ($options['return_type'] != 'boolean' &&
                $options['return_type'] != 'array' &&
                $options['return_type'] != 'both') {
                throw new InvalidArgumentException();
            }
        }

        // Loop through roles and permissions and check each.
        $checkedRoles = [];
        $checkedPermissions = [];
        foreach ($roles as $role) {
            $checkedRoles[$role] = $this->hasRole($role);
        }
        foreach ($permissions as $permission) {
            $checkedPermissions[$permission] = $this->can($permission);
        }

        // If validate all and there is a false in either
        // Check that if validate all, then there should not be any false.
        // Check that if not validate all, there must be at least one true.
        if(($options['validate_all'] && !(in_array(false,$checkedRoles) || in_array(false,$checkedPermissions))) ||
            (!$options['validate_all'] && (in_array(true,$checkedRoles) || in_array(true,$checkedPermissions)))) {
            $validateAll = true;
        } else {
            $validateAll = false;
        }

        // Return based on option
        if ($options['return_type'] == 'boolean') {
            return $validateAll;
        } elseif ($options['return_type'] == 'array') {
            return ['roles' => $checkedRoles, 'permissions' => $checkedPermissions];
        } else {
            return [$validateAll, ['roles' => $checkedRoles, 'permissions' => $checkedPermissions]];
        }

    }

    /**
     * Alias to eloquent many-to-many relation's attach() method.
     *
     * @param object|int|array $role
     */
    public function attachRole($role)
    {
        $role = $this->_getId($role);
        $this->roles()->attach($role);
    }

    /**
     * Alias to eloquent many-to-many relation's detach() method.
     *
     * @param mixed $role
     * @throws Exception
     */
    public function detachRole($role)
    {
        $role = $this->_getId($role);
        $this->roles()->detach($role);
    }

    /**
     * Attach multiple roles to a user
     *
     * @param array $rolesArray   array of arrays with required params from $this->attachRole()
     */
    public function attachRoles(array $rolesArray)
    {
        foreach ($rolesArray as $array) {
            $this->attachRole($array[0],$array[1],$array[2]);
        }
    }

    /**
     * Detach multiple roles from a user
     *
     * @param mixed $roles
     */
    public function detachRoles($roles=null)
    {
        if (!$roles) $roles = $this->roles()->get();
        
        foreach ($roles as $role) {
            $this->detachRole($role);
        }
    }

    /**
     * Get the Id of the item
     *
     * @param object|array|int $item
     * @return int
     * @throws \InvalidParameterException
     */
    protected function _getId($item)
    {
        if (is_object($item) ) {
            $item = $item->getKey();
        } else if (is_array($item) ) {
            $item = $item['id'];
        } else if (!is_int($item)) {
            throw new InvalidParameterException(__FUNCTION__ . ': Could not get Id: Parameter must be an object, array, or integer.');
        }

        return $item;
    }

}
