<?php

namespace Modules\EIdentity\Http\Controllers;

use Illuminate\Contracts\Support\Renderable;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Modules\EIdentity\Entities\BPS;
use Modules\EIdentity\Entities\Departments;
use Modules\EIdentity\Entities\Designations;
use Modules\EIdentity\Entities\EmployeeCategory;
use Modules\EIdentity\Entities\Employees;
use Modules\EIdentity\Entities\GuzzetedStatus;
use Modules\Settings\Entities\Company;
use Modules\Settings\Entities\MyApp;

class EIdentityController extends Controller
{
    /**
     * Display a listing of the resource.
     * @return Renderable
     */
    public function index()
    {
        $user = Auth::user();
        $department_id = $user->company_id;

        $total_employees =Employees::where(['user_id'=>$user->id])
                            ->whereNotIn('user_id',[355,354])
                            ->count();

        $total_pending =Employees::where(['user_id'=>$user->id])
                            ->whereRaw('(profile_picture IS NULL OR mobile_no IS NULL)')
                            ->whereNotIn('user_id',[355,354])
                            ->count();

        // this is incorrect - you should use "ADN" instead of "OR"
        $total_update =Employees::where(['user_id'=>Auth::id()])
                            ->whereRaw('(profile_picture IS NOT NULL AND mobile_no IS NOT NULL)')
                            ->whereNotIn('user_id',[355,354])
                            ->count();

        $overall_employees_counts =Employees::query()
                                                ->selectRaw(
                                                    'COUNT(1) as total_employees, 
                                                    COUNT(IF(mobile_no IS NOT NULL AND deleted_at IS NULL,1,NULL)) as total_employees_mobile_no_filled, 
                                                    COUNT(IF(mobile_no IS NULL AND deleted_at IS NULL,1,NULL)) as total_employees_mobile_no_pending, 
                                                    COUNT(IF(profile_picture IS NOT NULL AND deleted_at IS NULL,1,NULL)) as total_employees_profile_pic_filled,
                                                    COUNT(IF(profile_picture IS NULL AND deleted_at IS NULL,1,NULL)) as total_employees_profile_pic_pending
                                                    '
                                                )
                                                ->whereNotIn('user_id',[355,354])
                                                ->whereNull('deleted_at')
                                                ->first();


        //pr($overall_employees_counts->toArray());

        $data = [
            'title'=>'Dashboard',
            'total_employees'=>$total_employees,
            'total_pending'=>$total_pending,
            'total_update'=>$total_update,
            'overall_employees_counts'=>$overall_employees_counts,
        ];

        return view('eidentity::index',$data);
    }

    public function list()
    {
        $employees = Employees::with(['bpsMF','designationMF'])
                    ->where(['user_id'=>Auth::id()])
                    ->orderByDesc('bps_id')
                    ->get();

//        pr($employees->toArray());
//        return "";

        $data = [
            'title' => 'Employees  List',
            'new_route' => ['eidentity.employee.create', 'New Employee'],
            'employees' => $employees
        ];

        return view('eidentity::employees.list',$data);
    }

    /**
     * Show the form for creating a new resource.
     * @return Renderable
     */
    public function create()
    {

        $item               = new Employees();

        $bps_dd             = BPS::pluck('title','id');
        $employee_category  = EmployeeCategory::pluck('title','id');
        $designations       = Designations::pluck('title','id');
        $departments        = Company::whereNot('id',1)->orderBy('title','ASC')->pluck('title','id');
        $guzzeted_status    = GuzzetedStatus::pluck('title','id');

//print_r($item);
        $data = [
            'title' => 'Update Employee',
            'back_route' => ['eidentity.employee.list', 'Apps List'],
            'new_route' => ['eidentity.employee.create', 'New Employee'],
            'item' => $item,
            'bps_dd'=>$bps_dd,
            'employee_category'=>$employee_category,
            'designations'=>$designations,
            'departments'=>$departments,
            'guzzeted_status'=>$guzzeted_status,
        ];

        return view('eidentity::employees.form',$data);
    }

    /**
     * Store a newly created resource in storage.
     * @param Request $request
     * @return Renderable
     */
    public function store(Request $request)
    {

        $request->validate([
            'department_id'=>"required|integer",
            'personnel_no'=>'required',
            'employee_name'=>"required|alpha_spaces|min:2|max:32",
            'father_name'=>"required|alpha_spaces|min:2|max:32",
            'mobile_no'=>"required|min:10|max:14",
            'bps_id'=>"required|integer",
            'employee_category_id'=>"required|integer",
            'guzzeted_id'=>"required|integer",
            'designation_id'=>"required|integer",
            'cnic'=>"required|integer",
            'dob'=>"required|date",
            'date_of_appointment'=>"required|date",
            'profile_picture'=>'mimes:jpg,bmp,png,tiff,jpeg'
        ],[
            'alpha_spaces'=>'only alpha charters(a-z A-Z) with space are acceptable'
        ]);

        $item     = new Employees();
        $fill_rec = $item->fill($request->all());
        $user = Auth::user();
        $user_id = $user->id;
        $ipms_department_id = $user->company_id;
        //profile picture upload
        if($request->hasFile('profile_picture')){

            // Get filename with the extension
            $filenameWithExt = $request->file('profile_picture')->getClientOriginalName();
            //Get just filename
            $filename = pathinfo($filenameWithExt, PATHINFO_FILENAME);
            // Get just ext
            $extension = $request->file('profile_picture')->getClientOriginalExtension();
            // Filename to store
            $fileNameToStore = unique_name().'.'.strtolower($extension);
            // Upload Image
            $path = $request->file('profile_picture')->storeAs('public/eidentity',$fileNameToStore);

            \request()->request->set('profile_picture',$fileNameToStore);

            $fill_rec->profile_picture = $fileNameToStore;
        }


        //save record
        $fill_rec->user_id = $user_id;
        $update   =$fill_rec->save();

        if($update){
            session()->flash('success','Employee record added successfully!');
            return to_route('eidentity.employee.list');
        }

        session()->flash('error','Employee record not, Please check again!');
        return to_route('eidentity.employee.list');
    }

    /**
     * Show the specified resource.
     * @param int $id
     * @return Renderable
     */
    public function show($id)
    {
        return view('eidentity::show');
    }

    /**
     * Show the form for editing the specified resource.
     * @param int $id
     * @return Renderable
     */
    public function edit($id)
    {

        $item               = Employees::with(['bpsMF','employeeCategory','designationMF','guzzetedStatus'])
                             ->find(Crypt::decrypt($id));

        $bps_dd             = BPS::pluck('title','id');
        $employee_category  = EmployeeCategory::pluck('title','id');
        $designations       = Designations::pluck('title','id');
        $departments        = Company::whereNot('id',1)->orderBy('title','ASC')->pluck('title','id');
        $guzzeted_status    = GuzzetedStatus::pluck('title','id');

//print_r($item);
        $data = [
            'title' => 'Update Employee',
            'back_route' => ['eidentity.employee.list', 'Apps List'],
            'new_route' => ['eidentity.employee.create', 'New Employee'],
            'item' => $item,
            'bps_dd'=>$bps_dd,
            'employee_category'=>$employee_category,
            'designations'=>$designations,
            'departments'=>$departments,
            'guzzeted_status'=>$guzzeted_status,
        ];


        return view('eidentity::employees.form',$data);
    }

    /**
     * Update the specified resource in storage.
     * @param Request $request
     * @param int $id
     * @return Renderable
     */
    public function update(Request $request, $id)
    {
        $request->validate([
            'department_id'=>"required|integer",
            'personnel_no'=>'required',
            'employee_name'=>"required|alpha_spaces|min:2|max:32",
            'father_name'=>"required|alpha_spaces|min:2|max:32",
            'mobile_no'=>"required|min:10|max:14",
            'bps_id'=>"required|integer",
            'employee_category_id'=>"required|integer",
            'guzzeted_id'=>"required|integer",
            'designation_id'=>"required|integer",
            'cnic'=>"required|integer",
            'dob'=>"required|date",
            'date_of_appointment'=>"required|date",
            'profile_picture'=>'mimes:jpg,bmp,png,tiff,jpeg'
        ],[
            'alpha_spaces'=>'only alpha charters(a-z A-Z) with space are acceptable'
        ]);

        $item     = Employees::with(['bpsMF','employeeCategory','designationMF'])->find(Crypt::decrypt($id));
        $fill_rec = $item->fill($request->all());

        //profile picture upload
        if($request->hasFile('profile_picture')){

            // Get filename with the extension
            $filenameWithExt = $request->file('profile_picture')->getClientOriginalName();
            //Get just filename
            $filename = pathinfo($filenameWithExt, PATHINFO_FILENAME);
            // Get just ext
            $extension = $request->file('profile_picture')->getClientOriginalExtension();
            // Filename to store
            $fileNameToStore = unique_name().'.'.strtolower($extension);
            // Upload Image
            $path = $request->file('profile_picture')->storeAs('public/eidentity',$fileNameToStore);

            \request()->request->set('profile_picture',$fileNameToStore);

            $fill_rec->profile_picture = $fileNameToStore;
        }


        //save record
        $update   =$fill_rec->save();

        if($update){
            session()->flash('success','Employee record updated successfully!');
            return to_route('eidentity.employee.list');
        }

        session()->flash('error','Employee record not, Please check again!');
        return to_route('eidentity.employee.list');

    }

    /**
     * Remove the specified resource from storage.
     * @param int $id
     * @return Renderable
     */
    public function destroy($id)
    {
        $id         = decrypt($id);
        $employee   = Employees::find($id);

        if($employee->delete()){
            session()->flash('success', 'Employee deleted successfully');
            return redirect()->back();
        }


        session()->flash('error', 'Something went wrong, please try later');
        return redirect()->back();

    }

    public function departmentWiseReport(Request $request){

        $departments = Company::query()
            ->where('id','>',1)
            ->withCount([
                'employees'=>function($q){
                    $q->whereNull('deleted_at');
                },
                'employees as pending_mobile'=>function($q){
                    $q->whereNull('mobile_no')
                    ->whereNull('deleted_at');
                },
                'employees as pending_profile_pic'=>function($q){
                    $q->whereNull('profile_picture')
                        ->whereNull('deleted_at');
                }
            ])->whereNotIn('id',[355, 354])
            ->whereNull('deleted_at')
            ->get();

        $sql = "SELECT
                d.id,
                d.title as title,
                count(e.id) as employees_count,
                count(if(e.mobile_no is null or profile_picture is null, 1, null)) as pending_update,
                count(if(e.mobile_no is null, 1, null)) as pending_mobile,
                count(if(e.profile_picture is null, 1, null)) as pending_profile_pic
                
                from ".env('DB_DATABASE').".companies as d 
                left join ".env('DB_DATABASE').".users as u on d.id = u.company_id
                left join employees as e on u.id = e.user_id
                
                WHERE
                u.id not in (2,354,355,356)
                and d.id not in (353)
                and e.deleted_at is null
                
                GROUP by d.id 
                ORDER by d.title asc";

        $departments = DB::connection('eidentity')->select($sql);

        //pr($departments->toArray(),true);
        $data = [
            'title'=>'Department Wise Report',
            'departments'=>$departments,

        ];

        return view('eidentity::reports.department-wise',$data);

    }
}
