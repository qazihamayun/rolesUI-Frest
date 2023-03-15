<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::prefix('eidentity')->middleware(['auth'])->group(function() {
    Route::prefix('employee')->group(function (){

        Route::get('/', 'EIdentityController@index')->name('eidentity.employee.dashboard');
        Route::get('/list', 'EIdentityController@list')->name('eidentity.employee.list');
        Route::get('/new', 'EIdentityController@create')->name('eidentity.employee.create');
        Route::post('/store', 'EIdentityController@store')->name('eidentity.employee.store');

        Route::get('/edit{id}', 'EIdentityController@edit')->name('eidentity.employee.edit');
        Route::put('/edit{id}', 'EIdentityController@update')->name('eidentity.employee.update');

        Route::delete('/delete/{id}', 'EIdentityController@destroy')->name('eidentity.employee.delete');

        Route::prefix('reports')->group(function (){
            Route::get('/department-wise', 'EIdentityController@departmentWiseReport')->name('eidentity.employee.report-departmentwise');
        });

    });

});
