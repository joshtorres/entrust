<?php namespace Zizaco\Entrust\Traits;

/**
 * This file is part of Entrust,
 * a role & permission management solution for Laravel.
 *
 * @license MIT
 * @package Zizaco\Entrust
 */

use App\Permission;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Cache;

trait EntrustRoleTrait
{
    //Big block of caching functionality.
    public function cachedPermissions()
    {
        $rolePrimaryKey = $this->primaryKey;
        $cacheKey = 'entrust_permissions_for_role_'.$this->$rolePrimaryKey;
//        return Cache::tags(Config::get('entrust.permission_role_table'))->remember($cacheKey, Config::get('cache.ttl'), function () {
            return $this->perms()->get();
//        });
    }
    public function save(array $options = [])
    {   //both inserts and updates
        if(!parent::save($options)){
            return false;
        }
        Config::get('entrust.permission_role_table');
        return true;
    }
    public function delete(array $options = [])
    {   //soft or hard
        if(!parent::delete($options)){
            return false;
        }
        Config::get('entrust.permission_role_table');
        return true;
    }
    public function restore()
    {   //soft delete undo's
        if(!parent::restore()){
            return false;
        }
        Config::get('entrust.permission_role_table');
        return true;
    }

    /**
     *  Check role level and return the string value of the level based on range that it is in
     */
    public function checkRoleLevel()
    {
        // @TODO [churchapp]:[Josh] - plan out and create a role system based on these levels so the user can create their own role names such as Ministry Leader,etc.
        // super admin is 0
            // - no restrictions
        // billing admin 1-9
            // - has access to billing
        // admin is 10-99
            // - can access everything except billing info
        // editor is 100-199
            // - can create, edit, and delete resources
            // - cannot change users, or team information
        // reviewer is 200-299
            // - can only view and edit resources
        // viewer is 300-399
            // - can only view resources
        // scheduled / included viewer is 400-499
            // - can only view resources, when scheduled or included in the resource ( they must have a title for the specific event/resource)
        // subscriber is 500-599
            // - can only view resources tagged as "public"

    }

    /**
     * Returns the Module associated with this Role
     *
     * @return mixed
     */
    public function module()
    {
        return $this->belongsTo('App\Module','module_id');
    }

    /**
     * Returns the Team associated with this Role
     *
     * @return mixed
     */
    public function team()
    {
        return $this->belongsTo('App\Team');
    }

    /**
     * Many-to-Many relations with the user model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function users()
    {
        return $this->belongsToMany(Config::get('auth.providers.users.model'), Config::get('entrust.role_user_table'),Config::get('entrust.role_foreign_key'),Config::get('entrust.user_foreign_key'))->withPivot(['team_id']);
    }

    /**
     * Many-to-Many relations with the permission model.
     * Named "perms" for backwards compatibility. Also because "perms" is short and sweet.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function perms()
    {
        return $this->belongsToMany(Config::get('entrust.permission'), Config::get('entrust.permission_role_table'), Config::get('entrust.role_foreign_key'), Config::get('entrust.permission_foreign_key'));
    }

    /**
     * Boot the role model
     * Attach event listener to remove the many-to-many records when trying to delete
     * Will NOT delete any records if the role model uses soft deletes.
     *
     * @return void|bool
     */
    public static function boot()
    {
        parent::boot();

        static::deleting(function($role) {
            if (!method_exists(Config::get('entrust.role'), 'bootSoftDeletes')) {
                $role->users()->sync([]);
                $role->perms()->sync([]);
            }

            return true;
        });
    }
    
    /**
     * Checks if the role has a permission by its name.
     *
     * @param string|array $name       Permission name or array of permission names.
     * @param bool         $requireAll All permissions in the array are required.
     *
     * @return bool
     */
    public function hasPermission($permission, $requireAll = false)
    {
        if (is_array($permission)) {
            foreach ($permission as $permissionName) {
                $hasPermission = $this->hasPermission($permissionName);

                if ($hasPermission && !$requireAll) {
                    return true;
                } elseif (!$hasPermission && $requireAll) {
                    return false;
                }
            }

            // If we've made it this far and $requireAll is FALSE, then NONE of the permissions were found
            // If we've made it this far and $requireAll is TRUE, then ALL of the permissions were found.
            // Return the value of $requireAll;
            return $requireAll;
        } else {
            if ( is_int($permission) ) {
                $permission = Permission::findOrFail($permission)->name;
            }
            foreach ($this->cachedPermissions() as $permission) {
                if ($permission->name == $permission) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Save the inputted permissions.
     *
     * @param mixed $inputPermissions
     *
     * @return void
     */
    public function savePermissions($inputPermissions)
    {
        if (!empty($inputPermissions)) {
            $this->perms()->sync($inputPermissions);
        } else {
            $this->perms()->detach();
        }
    }

    /**
     * Attach permission to current role.
     *
     * @param object|array $permission
     *
     * @return void
     */
    public function attachPermission($permission)
    {
        if (is_object($permission)) {
            $permission = $permission->getKey();
        }

        if (is_array($permission)) {
            $permission = $permission['id'];
        }

        if ( !$this->hasPermission($permission) ) {
            $this->perms()->attach($permission);
        }
    }

    /**
     * Detach permission from current role.
     *
     * @param object|array $permission
     *
     * @return void
     */
    public function detachPermission($permission)
    {
        if (is_object($permission))
            $permission = $permission->getKey();

        if (is_array($permission))
            $permission = $permission['id'];

        $this->perms()->detach($permission);
    }

    /**
     * Attach multiple permissions to current role.
     *
     * @param mixed $permissions
     *
     * @return void
     */
    public function attachPermissions($permissions)
    {
        foreach ($permissions as $permission) {
            $this->attachPermission($permission);
        }
    }

    /**
     * Detach multiple permissions from current role
     *
     * @param mixed $permissions
     *
     * @return void
     */
    public function detachPermissions($permissions)
    {
        foreach ($permissions as $permission) {
            $this->detachPermission($permission);
        }
    }
}
