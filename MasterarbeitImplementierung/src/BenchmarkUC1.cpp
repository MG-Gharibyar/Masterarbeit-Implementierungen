#define PROFILE

#include "openfhe.h"
#include <json/json.h>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;



struct FleetData {
    std::vector<double> driverIDs;
    std::vector<double> locLat;
    std::vector<double> locLong;
    std::vector<double> distanceTravelled;
    std::vector<double> co2Emissions;
    std::vector<double> emissionFactor;
    std::vector<double> speed;
    std::vector<double> fuelConsumption;
    std::vector<double> cargoWeight;
};

struct FleetDataCipher {
    Ciphertext<DCRTPoly> driverIDs;
    Ciphertext<DCRTPoly> locLat;
    Ciphertext<DCRTPoly> locLong;
    Ciphertext<DCRTPoly> distanceTravelled;
    Ciphertext<DCRTPoly> co2Emissions;
    Ciphertext<DCRTPoly> emissionFactor;
    Ciphertext<DCRTPoly> speed;
    Ciphertext<DCRTPoly> fuelConsumption;
    Ciphertext<DCRTPoly> cargoWeight;
};

std::map<int, FleetData> fleetMap;

struct Results {
    std::string TimeStamp       = "";  
    std::string Comment         = "";
    int Batchsize               = -1;  
    int ScalingTechnique        = -1;
    int LevelAfterBootstrapping = -1;
    int ScaleModSize            = -1;
    int FirstModSize            = -1;
    int RingDimension           = -1;
    int MultiplicativeDepth     = -1;
    int LevelBudget             = -1;
    double Log2q                = -1.0;     //Log2(q) von Ciphertext Modulus zur Bewertung der Sicherheitsstufe

    // all durations are measured in ms
    int DurOverall              = -1;       //Overall duration of benchmarking one parameter set
    double DurEncryption        = -1.0;     //Duration to encrypt and bootstrap all vectors of RawInput
    double DurDecryption        = -1.0;     //Duration to decrypt the 3 result vectors
    double DurEncoding          = -1.0;     //Duration to encode plaintext
    double CO2e_Dur             = -1.0;     //Duration for whole CO2e calculation incl. bootstrapping
    int CO2e_BS_Dur             = -1;       //Duration of bootstrapping with one iteration
    int CO2e_BS_DurRaiseMod     = 0;        //Duration of bootstrapping pipeline (one iter): Raising the modulus
    int CO2e_BS_DurCoeffsToSlot = 0;        //Duration of bootstrapping pipeline (one iter): CoeffsToSlot
    int CO2e_BS_DurSine         = 0;        //Duration of bootstrapping pipeline (one iter): Approximate mod reduction
    int CO2e_BS_DurSlotsToCoeff = 0;        //Duration of bootstrapping pipeline (one iter): SlotsToCoeff
    int CO2e_BS_LvlAfter        = -1;       //Level after Bootstrapping
    double CO2e_BS_Throughput   = -1.0;
    double CO2e_Calc_DurCalcMult    = 0;    //Duration of multiplication in CO2e calculation
    double PCor_Calc_DurCalcMean    = 0;    //Duration of mean calculation in CO2e calculation
    double CO2e_BS_PrecAfter    = -1.0;     //precision of CO2e result in bit after Bootstrapping
    double CO2e_Calc_PrecAfter  = -1.0;     //precision of CO2e result in bit before Bootstrapping
    double CO2e_Calc_Dur        = -1.0;     //Duration of calculating CO2e on the first cipher text
    int CO2e_Calc_LvlBefore     = -1;
    int CO2e_Calc_LvlAfter      = -1;
    double Var_Dur              = -1.0;     //Duration for whole variance calculation incl. bootstrapping
    int Var_BS_Dur              = -1;       //Duration of bootstrapping with one iteration
    int Var_BS_DurRaiseMod      = 0;        //Duration of bootstrapping pipeline (one iter): Raising the modulus
    int Var_BS_DurCoeffsToSlot  = 0;        //Duration of bootstrapping pipeline (one iter): CoeffsToSlot
    int Var_BS_DurSine          = 0;        //Duration of bootstrapping pipeline (one iter): Approximate mod reduction
    int Var_BS_DurSlotsToCoeff  = 0;        //Duration of bootstrapping pipeline (one iter): SlotsToCoeff
    int Var_BS_LvlAfter         = -1;
    double Var_BS_Throughput    = -1.0;
    double Var_Calc_DurCalcMean = 0.0;      //Duration of add many in variance calculation
    double Var_Calc_DurCalcSub  = 0.0;      //Duration of substraction in variance calculation
    double Var_Calc_DurCalcSq   = 0.0;      //Duration of square in variance calculation    
    double Var_Calc_Dur         = -1.0;     //Duration of calculating variance of all cipher text
    double Var_BS_PrecAfter     = -1.0;     //precision of CO2e result in bit after Bootstrapping
    double Var_Calc_PrecAfter   = -1.0;     //precision of CO2e result in bit before Bootstrapping
    int Var_Calc_LvlBefore      = -1;
    int Var_Calc_LvlAfter       = -1;
    double SDev_Dur              = -1.0;    //Duration for whole standard deviation calculation incl. bootstrapping
    int SDev_BS_Dur              = -1;      //Duration of bootstrapping with one iteration
    int SDev_BS_DurRaiseMod      = 0;       //Duration of bootstrapping pipeline (one iter): Raising the modulus
    int SDev_BS_DurCoeffsToSlot  = 0;       //Duration of bootstrapping pipeline (one iter): CoeffsToSlot
    int SDev_BS_DurSine          = 0;       //Duration of bootstrapping pipeline (one iter): Approximate mod reduction
    int SDev_BS_DurSlotsToCoeff  = 0;       //Duration of bootstrapping pipeline (one iter): SlotsToCoeff
    int SDev_BS_LvlAfter         = -1;
    double SDev_BS_Throughput    = -1.0;
    double SDev_Calc_DurCalcMean = 0;       //Duration of add many in standard deviation calculation
    double SDev_Calc_DurCalcSub  = 0.0;     //Duration of substraction in standard deviation calculation
    double SDev_Calc_DurCalcSq   = 0.0;     //Duration of square in standard deviation calculation    
    double SDev_Calc_Dur         = -1.0;    //Duration of calculating variance of all cipher text
    double SDev_BS_PrecAfter     = -1.0;    //precision of standard deviation result in bit after Bootstrapping
    double SDev_Calc_PrecAfter   = -1.0;    //precision of standard deviation result in bit before Bootstrapping
    int SDev_Calc_LvlBefore      = -1;
    int SDev_Calc_LvlAfter       = -1;
    double PCor_Dur              = -1.0;    // Duration for whole pearson correlation calculation incl. bootstrapping
    int PCor_BS_Dur              = -1;      //Duration of bootstrapping with one iteration
    int PCor_BS_DurRaiseMod      = 0;       //Duration of bootstrapping pipeline (one iter): Raising the modulus
    int PCor_BS_DurCoeffsToSlot  = 0;       //Duration of bootstrapping pipeline (one iter): CoeffsToSlot
    int PCor_BS_DurSine          = 0;       //Duration of bootstrapping pipeline (one iter): Approximate mod reduction
    int PCor_BS_DurSlotsToCoeff  = 0;       //Duration of bootstrapping pipeline (one iter): SlotsToCoeff
    int PCor_BS_LvlAfter         = -1;
    double PCor_BS_Throughput    = -1.0;
    double PCor_Calc_DurCalcSq   = 0.0;     //Duration of add many in PCoriance calculation
    double PCor_Calc_DurCalcDiv  = 0.0;     //Duration of division in PCoriance calculation
    double PCor_Calc_DurCalcRSq  = 0.0;     //Duration of square in PCoriance calculation    
    double PCor_Calc_Dur         = -1.0;    //Duration of calculating PCoriance of all cipher text
    double PCor_BS_PrecAfter     = -1.0;    //precision of CO2e result in bit after Bootstrapping
    double PCor_Calc_PrecAfter   = -1.0;    //precision of CO2e result in bit before Bootstrapping
    int PCor_Calc_LvlBefore      = -1;
    int PCor_Calc_LvlAfter       = -1;
    // all sizes are measured in kb
    int SizeCryptoContext       = -1;   //size of crypto context
    int SizeEvalMultKey         = -1;   //size of MultKey
    int SizeRotKey              = -1;   //size of RotKey
    int SizeData                = -1;   //size of ciphertext
    // throughput is measured in kb/s
    double ThroughputEncryption = -1.0;
    double ThroughputDecryption = -1.0;
    std::string CO2e_ResExp     = "";   //string output of expected CO2e result
    std::string CO2e_ResAct     = "";   //string output of actual CO2e result
    std::string PCor_ResExp     = "";   //string output of expected mean result
    std::string PCor_ResAct     = "";   //string output of actual mean result
    std::string Var_ResExp      = "";   //string output of expected variance result
    std::string Var_ResAct      = "";   //string output of actual variance result
    std::string SDev_ResExp     = "";   //string output of expected standard deviation result
    std::string SDev_ResAct     = "";   //string output of actual standard deviation result
};

class FHEBenchmark {
    private:
        CryptoContext<DCRTPoly> cryptoContext;
        KeyPair<DCRTPoly> keyPair;        
        std::map<int, FleetDataCipher> CipherInput;
        std::vector<Ciphertext<DCRTPoly>> CO2eResult;
        std::vector<Ciphertext<DCRTPoly>> PCorResult;
        std::vector<Ciphertext<DCRTPoly>> VarResult;
        std::vector<Ciphertext<DCRTPoly>> SDevResult;
        uint32_t numSlots;
        usint depth;
        std::vector<uint32_t> levelBudget;
        std::vector<uint32_t> bsgsDim;
        std::vector<double> RawCO2e, RawPCor, RawVar, RawSDev;
        Results bm_results;

        /**
         * Calculates the CO2e (carbon dioxide equivalent) for each element in the input vector.
         * CO2e is calculated as sum of (CargoWeight * distanceTravelled * EmissionFactor).
         *
         * @param input The input vector of doubles.
         * @return The vector containing the CO2e values.
         */
        std::vector<double> CalcPlaintextCO2e() {

            std::vector<double> result;

            for (const auto& [truckId, data] : fleetMap) {
                double co2e = 0.0;

                for(size_t i = 0; i < data.cargoWeight.size(); i++){
                    co2e += data.cargoWeight[i] * data.distanceTravelled[i] * data.emissionFactor[i];
                }
                result.push_back(co2e);
            }

            return result;
        }

        /**
         * Calculates the mean value for each element in the input vector of vectors.
         *
         * @param input The input vector of vectors of doubles.
         * @return The vector containing the mean values.
         */
        std::vector<double> CalcPlaintextPearsonCorr() {
            int n = fleetMap[0].cargoWeight.size();    // number of data points

            std::vector<double> result;

            for (const auto& [truckId, data] : fleetMap) {

                // calculate mean values of fuel consumption and cargo weight
                // fuel consumption = input[6]
                // cargo weight = input[7]
                double meanFuelConsumption = 0.0, meanCargoWeight = 0.0;
                for (int i = 0; i < n; ++i) {
                    meanFuelConsumption += data.fuelConsumption[i];
                    meanCargoWeight += data.cargoWeight[i];
                }

                meanFuelConsumption /= n;
                meanCargoWeight /= n;

                // calculate sum of products of the deviations
                double sum_product_deviations = 0.0, sum_squared_fuelcons = 0.0, sum_squared_cargow = 0.0;
                for (int i = 0; i < n; ++i) {
                    double devFuelCons = data.fuelConsumption[i] - meanFuelConsumption;
                    double devCargoW = data.cargoWeight[i] - meanCargoWeight;
                    sum_product_deviations += devFuelCons * devCargoW;
                    sum_squared_fuelcons += devFuelCons * devFuelCons;
                    sum_squared_cargow += devCargoW * devCargoW;
                }

                // calculate correlation coefficients
                double correlation_coefficient = sum_product_deviations / (sqrt(sum_squared_fuelcons) * sqrt(sum_squared_cargow));
                result.push_back(correlation_coefficient);
            }

            // return as vec
            return result;
        }

        
        /**
         * Calculates the variance of fuel consumption.
         *
         * @param input The input vector of vectors of doubles.
         * @return The vector containing the variance values.
         */
        std::vector<double> CalcPlaintextVar() {
            int n = fleetMap[0].cargoWeight.size();    // number of data points
            std::vector<double> result;

            for (const auto& [truckId, data] : fleetMap) {

                double mean = 0.0;
                for(int i = 0; i < n; i++){
                    mean += data.fuelConsumption[i];
                }
                mean /= n;

                // Sum (x_i - µ)^2 calculation
                double sum = 0.0;
                for(int i = 0; i < n; i++){
                     sum += std::pow((data.fuelConsumption[i]- mean),2);
                }

                sum /= n;

                result.push_back(sum);
            }

            return result;
        }

        /**
         * Calculates the standard deviation for each element in the input vector of vectors.
         *
         * @param input The input vector of vectors of doubles.
         * @return The vector containing the variance values.
         */
        std::vector<double> CalcPlaintextSDev() {
            int n = fleetMap[0].cargoWeight.size();    // number of data points
            std::vector<double> result;

            for (const auto& [truckId, data] : fleetMap) {

                double mean = 0.0;
                for(int i = 0; i < n; i++){
                    mean += data.fuelConsumption[i];
                }
                mean /= n;

                // Sum (x_i - µ)^2 calculation
                double sum = 0.0;
                for(int i = 0; i < n; i++){
                     sum += std::pow((data.fuelConsumption[i]- mean),2);
                }

                sum /= n;

                result.push_back(std::sqrt(sum));
            }

            return result;
        }

        /**
         * Calculates the approximation error between two vectors of complex numbers.
         *
         * @param result The vector containing the calculated complex numbers.
         * @param expectedResult The vector containing the expected complex numbers.
         * @return The approximation error.
         * @throws config_error if the vectors have different sizes.
         */
        double CalculateApproximationError(const std::vector<double>& result,
                                            const std::vector<double>& expectedResult) {
            if (result.size() != expectedResult.size())
                OPENFHE_THROW(config_error, "Cannot compare vectors with different numbers of elements");

            // Using the infinity norm
            double maxError = 0;
            for (size_t i = 0; i < result.size(); ++i) {
                double error = std::abs(result[i] - expectedResult[i]);
                if (maxError < error)
                    maxError = error;
            }

            return std::log2(maxError);
        }

        /**
         * Calculates the approximation error between two vectors of complex numbers.
         *
         * @param result The vector containing the calculated complex numbers.
         * @param expectedResult The vector containing the expected complex numbers.
         * @return The approximation error.
         * @throws config_error if the vectors have different sizes.
         */
        double CalculateApproximationError(const std::vector<double>& result,
                                            const std::vector<std::complex<double>>& expectedResult) {
            
            // Using the infinity norm
            double maxError = 0;
            for (size_t i = 0; i < result.size(); ++i) {
                double error = std::abs(result[i] - expectedResult[i].real());
                if (maxError < error)
                    maxError = error;
            }

            double prec = std::log2(maxError);

            if(std::isfinite(prec)) {
                return prec;
            }
            else{
                return -1.0;
            }
             
        }

        /**
         * Calculates the approximation error between two vectors of complex numbers.
         *
         * @param result The vector containing the calculated complex numbers.
         * @param expectedResult The vector containing the expected complex numbers.
         * @param length How many entries shall be evaluated
         * @return The approximation error.
         * @throws config_error if the vectors have different sizes.
         */
        double CalculateApproximationError(const std::vector<double>& result,
                                            const std::vector<std::complex<double>>& expectedResult, int length) {
            
            // Using the infinity norm
            double maxError = 0;
            for (int i = 0; i < length; ++i) {
                double error = std::abs(result[i] - expectedResult[i].real());
                if (maxError < error)
                    maxError = error;
            }

            double prec = std::log2(maxError);

            if(std::isfinite(prec)) {
                return prec;
            }
            else{
                return -1.0;
            }
             
        }

        /**
         * Gets the current timestamp in the format "YYYY-MM-DD HH:MM:SS".
         *
         * @return The current timestamp as a string.
         */
        std::string getCurrentTimestamp() {
            // Get current time
            auto now = std::chrono::system_clock::now();
            std::time_t currentTime = std::chrono::system_clock::to_time_t(now);

            // Convert to tm struct
            std::tm tmTime = *std::localtime(&currentTime);

            // Using std::put_time to format date/time
            std::stringstream ss;
            ss << std::put_time(&tmTime, "%Y-%m-%d %H:%M:%S"); // Format: YYYY-MM-DD HH:MM:SS
            return ss.str();
        }

        /**
         * Prints the elements of a vector up to a specified number of elements.
         *
         * @param FirstText The text to print before the vector elements.
         * @param vec The vector to print.
         * @param numElements The number of elements to print (-1 to print all).
         */
        void printVector(std::string FirstText, const std::vector<double>& vec, int numElements = -1) {
            std::cout << FirstText;
            int count = 0;
            for (const auto& element : vec) {
                if (numElements == -1 || count < numElements) {
                    std::cout << std::fixed << std::setprecision(7) << element << " ";
                    count++;
                } else {
                    break;
                }
            }
            std::cout << std::endl;
        }

        /**
         * Converts a string of double values into a vector of doubles
         * @param str string that contains double values separated by space, comma or tabulator.
        */
        std::vector<double> stringToDoubleVector(const std::string& str) {
            std::vector<double> result;
            std::stringstream ss(str);

            double value;
            while (ss >> value) {
                result.push_back(value);

                while (ss.peek() == ' ' || ss.peek() == ',' || ss.peek() == '\t') {
                    ss.ignore();
                }
            }

            return result;
        }

        std::string vectorToFormattedString(const std::vector<double>& vec, int length) {
            std::ostringstream oss;

            for ( int i = 0; i < length; ++i) {
                oss << std::fixed << std::setprecision(10) << vec[i] << " ";
            }

            return oss.str();
        }

    public:
        FHEBenchmark(int rescaletech, int batchsize, int scalemodsize, int firstmodsize, int ringdim, int deslvl, usint lvlbudget){
            CCParams<CryptoContextCKKSRNS> parameters;
            SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
            parameters.SetSecretKeyDist(secretKeyDist);
            parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
            parameters.SetRingDim(ringdim);
            parameters.SetScalingModSize(scalemodsize);
            parameters.SetFirstModSize(firstmodsize);

            ScalingTechnique rescaleTech = FLEXIBLEAUTO;
            switch(rescaletech){
                case 1: rescaleTech = FIXEDAUTO;
                        break;
                case 2: rescaleTech = FLEXIBLEAUTO;
                        break;
                case 3: rescaleTech = FLEXIBLEAUTOEXT;
                        break;
                default:
                        std::cout << "Wrong input parameter for rescale technique" << std::endl;    
            }
            parameters.SetScalingTechnique(rescaleTech);

            // Here, we specify the number of iterations to run bootstrapping. Note that we currently only support 1 or 2 iterations.
            // Two iterations should give us approximately double the precision of one iteration.
            uint32_t numIterations = 1;

            levelBudget = {lvlbudget, lvlbudget};
            bsgsDim     = {0, 0};

            // multiplicative depth is sum of desired levels after bootstrapping and bootstrapping budget
            uint32_t levelsAvailableAfterBootstrap = deslvl;
            depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist) + (numIterations - 1)-15 ;
            parameters.SetMultiplicativeDepth(depth);

            // Generate crypto context.
            cryptoContext = GenCryptoContext(parameters);

            // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
            cryptoContext->Enable(PKE);
            cryptoContext->Enable(KEYSWITCH);
            cryptoContext->Enable(LEVELEDSHE);
            cryptoContext->Enable(ADVANCEDSHE);
            cryptoContext->Enable(FHE);

            // Step 2: Precomputations for bootstrapping
            // We use a sparse packing.
            numSlots = batchsize;
            cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);

            // Step 3: Key Generation
            keyPair = cryptoContext->KeyGen();
            cryptoContext->EvalMultKeyGen(keyPair.secretKey);
            // Generate bootstrapping keys.
            cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);
            cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1,2,3,-1,-2,-3});
            cryptoContext->EvalSumKeyGen(keyPair.secretKey, keyPair.publicKey);

            //Make calculations on plaintext
            RawCO2e = CalcPlaintextCO2e();
            RawPCor = CalcPlaintextPearsonCorr();
            RawVar  = CalcPlaintextVar();
            RawSDev = CalcPlaintextSDev();

            //Add input variables to json result file
            bm_results.TimeStamp                = getCurrentTimestamp();
            bm_results.Batchsize                = batchsize;
            bm_results.ScalingTechnique         = rescaletech;
            bm_results.ScaleModSize             = scalemodsize;
            bm_results.FirstModSize             = firstmodsize;
            bm_results.RingDimension            = cryptoContext->GetRingDimension();
            bm_results.MultiplicativeDepth      = depth;
            bm_results.LevelAfterBootstrapping  = levelsAvailableAfterBootstrap;
            bm_results.LevelBudget              = lvlbudget;

           double log2q = log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble());

            bm_results.Log2q = std::isinf(log2q) ? 10000.0 : log2q;

            //Calculate size of the keys
            std::stringstream s1, s2, s3;    
            size_t lengthInBytes;
            Serial::Serialize(cryptoContext, s1, SerType::BINARY);
            std::string str = s1.str();
            bm_results.SizeCryptoContext = sizeof(str[0]) * (str.length() + 1);

            cryptoContext->SerializeEvalMultKey(s2, SerType::BINARY);
            str = s2.str();
            lengthInBytes = sizeof(str[0]) * (str.length() + 1);
            bm_results.SizeEvalMultKey = lengthInBytes / 1024; //Display in kB

            cryptoContext->SerializeEvalAutomorphismKey(s3, SerType::BINARY);
            str = s3.str();
            lengthInBytes = sizeof(str[0]) * (str.length() + 1);
            bm_results.SizeRotKey = lengthInBytes / 1024; //Display in kB
        }

        /**
         * @brief Encrypt the raw input data of fleetMap and stores it into struct FleetDataCipher
        */
        void EncryptData(){
            
            TimeVar t;
            std::cout << "Start of encryption" << std::endl;
            // Encoding plaintexts             
            std::vector<double> result;
            double durEncoding = 0.0;
            double durEncryption = 0.0;

            for (const auto& [truckId, data] : fleetMap) {
                TIC(t);  //Start timer
                FleetDataCipher& datacipher = CipherInput[truckId];
                Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.cargoWeight, 1UL, 0U, nullptr, numSlots);
                ptxt->SetLength(numSlots);
                durEncoding += TOC_US(t) / 1000.0;
                TIC(t);
                datacipher.cargoWeight = cryptoContext->Encrypt(keyPair.secretKey, ptxt);
                durEncryption += TOC_US(t) / 1000.0;
                
                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.co2Emissions, 1UL, 0U, nullptr,numSlots);
                ptxt->SetLength(numSlots);
                durEncoding += TOC_US(t) / 1000.0;
                datacipher.co2Emissions = cryptoContext->Encrypt(keyPair.secretKey, ptxt);
                durEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.distanceTravelled, 1UL, 0U, nullptr,numSlots);
                ptxt->SetLength(numSlots);
                durEncoding += TOC_US(t) / 1000.0;
                datacipher.distanceTravelled = cryptoContext->Encrypt(keyPair.secretKey, ptxt);
                durEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.driverIDs, 1UL, 0U, nullptr,numSlots);
                ptxt->SetLength(numSlots);
                durEncoding += TOC_US(t) / 1000.0;
                datacipher.driverIDs = cryptoContext->Encrypt(keyPair.secretKey, ptxt);
                durEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.emissionFactor, 1UL, 0U, nullptr,numSlots);
                ptxt->SetLength(numSlots);
                durEncoding += TOC_US(t) / 1000.0;
                datacipher.emissionFactor = cryptoContext->Encrypt(keyPair.secretKey, ptxt);
                durEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.fuelConsumption, 1UL, 0U, nullptr,numSlots);
                ptxt->SetLength(numSlots);
                durEncoding += TOC_US(t) / 1000.0;
                datacipher.fuelConsumption = cryptoContext->Encrypt(keyPair.secretKey, ptxt);
                durEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.locLat, 1UL, 0U, nullptr,numSlots);
                ptxt->SetLength(numSlots);
                durEncoding += TOC_US(t) / 1000.0;
                datacipher.locLat = cryptoContext->Encrypt(keyPair.secretKey, ptxt);
                durEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.locLong, 1UL, 0U, nullptr,numSlots);
                ptxt->SetLength(numSlots);
                durEncoding += TOC_US(t) / 1000.0;
                datacipher.locLong = cryptoContext->Encrypt(keyPair.secretKey, ptxt);
                durEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.speed, 1UL, 0U, nullptr,numSlots);
                ptxt->SetLength(numSlots);
                durEncoding += TOC_US(t) / 1000.0;
                datacipher.speed = cryptoContext->Encrypt(keyPair.secretKey, ptxt);
                durEncryption += TOC_US(t) / 1000.0;

            }

            std::cout << "Size of fleetMap: " << fleetMap.size() << std::endl;

            bm_results.DurEncoding = durEncoding / (9 * fleetMap.size());
            bm_results.DurEncryption = durEncryption / (9 * fleetMap.size());

        }

        /**
         * @brief Decryption of result cipher texts to measure decryption time.
        */
        void Decrypt(){
            TimeVar t;  // Timer variable to measure execution time
            TIC(t);     // Start the timer

            try{
                // Decrypt the encrypted result
                int n = CO2eResult.size();

                for(int i = 0; i < n; i++){
                    Plaintext resultCO2e;
                    cryptoContext->Decrypt(keyPair.secretKey, CO2eResult[i], &resultCO2e);
                    resultCO2e->SetLength(numSlots);

                    // Decrypt the encrypted Pearson correlation result
                    Plaintext resultPCor;
                    cryptoContext->Decrypt(keyPair.secretKey, PCorResult[i], &resultPCor);
                    resultPCor->SetLength(numSlots);

                    // Decrypt the encrypted variance result
                    Plaintext resultVar;
                    cryptoContext->Decrypt(keyPair.secretKey, VarResult[i], &resultVar);
                    resultVar->SetLength(numSlots);

                    // Decrypt the encrypted variance result
                    Plaintext resultSDev;
                    cryptoContext->Decrypt(keyPair.secretKey, SDevResult[i], &resultSDev);
                    resultSDev->SetLength(numSlots);
                }
                
            
                // Record the duration of the CO2e calculation
                bm_results.DurDecryption = TOC_US(t) / 1000.0;
            }
            catch(const std::exception& e)
            {
                // Handle decryption errors
                bm_results.Comment = "Error while decrypting results";
                std::cerr << e.what() << '\n';
            }
        }

        /**
         * @brief Takes first element of ciphertext vector and calculates size of data
        */
        void SetDataSize(){
            std::stringstream s;
            Serial::Serialize(CipherInput[0].fuelConsumption, s, SerType::BINARY);
            std::string str = s.str();
            size_t lengthInBytes = sizeof(str[0]) * (str.length() + 1);
            bm_results.SizeData = lengthInBytes / 1024; //Display in kB
        }

        /**
         * @brief Calculates the encrypted result of CO2e (carbon dioxide equivalent) based on encrypted input values.
         */
        void CalcCipherCO2e(){
            TimeVar t, tmult; // Timer variable to measure execution time
            TIC(t); // Start the timer
            std::cout << "\nStart of CO2e calculation" << std::endl; // Print a message indicating the start of the CO2e calculation

            //==============================================================
            // CALCULATION
            //==============================================================

            std::vector<Ciphertext<DCRTPoly>> co2eresults;
            bm_results.CO2e_Calc_LvlBefore = CipherInput[0].fuelConsumption->GetLevel();
            std::cout << "\tLevel before CO2e calculation: " << CipherInput[0].fuelConsumption->GetLevel() << std::endl;

            
            for (const auto& [truckId, data] : CipherInput) {
                TIC(tmult);
                auto cm1 = cryptoContext->EvalMult(data.distanceTravelled, data.cargoWeight);
                auto cm2 = cryptoContext->EvalMult(data.emissionFactor, cm1);
                bm_results.CO2e_Calc_DurCalcMult += TOC_US(tmult) / 1000.0;
                cm2      = cryptoContext->EvalSum(cm2, numSlots);
                co2eresults.push_back(cm2);
               
            }
            
        
            std::cout << "\tLevel after CO2e calculation: " << co2eresults[0]->GetLevel() << std::endl;
            bm_results.CO2e_Calc_LvlAfter = co2eresults[0]->GetLevel();
            bm_results.CO2e_Calc_Dur = TOC_US(t) / 1000.0;

            //==============================================================
            // BOOTSTRAPPING
            //==============================================================
            // some modifications have been made in ckksrns-fhe.cpp in order to get 
            // a console output of bootstrapping timings.
            // The console output is redirected into a stringstream,
            // bootstrapping timings are extracted and then the
            // output is redirected to console again.
            

            
            TimeVar t_bs1;
            TIC(t_bs1);  //Start timer for first bootstrapping

            for(size_t i =0; i < co2eresults.size(); i++){
                std::stringstream output; // stream for output of openFHE lib
                std::streambuf* old_cout = std::cout.rdbuf(output.rdbuf()); //redirection of std::cout

                CO2eResult.push_back(cryptoContext->EvalBootstrap(co2eresults[i], 1U, 0U));
                std::cout.rdbuf(old_cout); // reset of std::cout
                std::vector<double> bstimings = stringToDoubleVector(output.str());

                bm_results.CO2e_BS_DurRaiseMod      += bstimings[0];
                bm_results.CO2e_BS_DurCoeffsToSlot  += bstimings[1];
                bm_results.CO2e_BS_DurSine          += bstimings[2];
                bm_results.CO2e_BS_DurSlotsToCoeff  += bstimings[3];

            }
            
            bm_results.CO2e_BS_LvlAfter = CO2eResult[0]->GetLevel();
            bm_results.CO2e_BS_Dur = TOC(t_bs1);
            
            try{
                // Decrypt the encrypted result
                std::vector<double> results, resultsbs;

                for(size_t i = 0; i < co2eresults.size(); i++)
                {
                    Plaintext resultCO2e, resultCO2eBS;
                    cryptoContext->Decrypt(keyPair.secretKey, co2eresults[i], &resultCO2e);
                    resultCO2e->SetLength(numSlots);

                    cryptoContext->Decrypt(keyPair.secretKey, CO2eResult[i], &resultCO2eBS);
                    resultCO2eBS->SetLength(numSlots);

                    results.push_back(resultCO2e->GetRealPackedValue()[0]);     //All elements of plaintext are equal therefore its sufficent to read first element
                    resultsbs.push_back(resultCO2eBS->GetRealPackedValue()[0]);
                }
                
                // Record the duration of the CO2e calculation
                bm_results.CO2e_Dur = TOC_US(t) / 1000.0;
                // Record the precision of the CO2e result
                bm_results.CO2e_Calc_PrecAfter = std::floor(CalculateApproximationError(RawCO2e, results));
                bm_results.CO2e_BS_PrecAfter = std::floor(CalculateApproximationError(RawCO2e, resultsbs));
                bm_results.CO2e_ResExp = vectorToFormattedString(RawCO2e, RawCO2e.size());
                bm_results.CO2e_ResAct = vectorToFormattedString(resultsbs, resultsbs.size());

                // Print the results of the CO2e calculation
                std::cout << "\nResults of CO2e calculation" << std::endl;
                printVector("\tExpected result:\t", RawCO2e, RawCO2e.size());
                printVector("\tActual result:\t\t", resultsbs, resultsbs.size());
                std::cout << "\tPrecision: " << bm_results.CO2e_BS_PrecAfter << " bits" << std::endl;
            }
            catch(const std::exception& e)
            {
                // Handle decryption errors
                bm_results.Comment = "Error while decrypting CO2e results";
                std::cerr << e.what() << '\n';
            }            
        }

        void DecryptSingleCipher(std::string name, Ciphertext<DCRTPoly> cipher){
            Plaintext pt;

            try{
                cryptoContext->Decrypt(keyPair.secretKey, cipher, &pt);

                printVector(name, pt->GetRealPackedValue());
            }
            catch(const std::exception& e)
            {
                // Handle decryption errors
                std::cerr << e.what() << '\n';
            }
        }

        /**
         * @brief Calculates the encrypted squared Pearson correlation coefficient of fuel consumption and cargo weight.
         */
        void CalcCipherPearsonCorr(){
            TimeVar t, tmean, trsq, tdiv, tsq; // Timer variable to measure execution time
            TIC(t); // Start the timer
            std::cout << "\nStart of Pearson correlation coefficients calculation" << std::endl; // Print a message indicating the start of the pcor calculation
            std::cout << "Level: " <<  CipherInput[0].fuelConsumption->GetLevel() << std::endl;

            std::vector<Ciphertext<DCRTPoly>> pcorresults;

            bm_results.PCor_Calc_LvlBefore = CipherInput[0].fuelConsumption->GetLevel();

            //==============================================================
            // CALCULATION
            //==============================================================
            
            for (const auto& [truckId, data] : CipherInput) {
                TIC(tmean);
                // Mean values of fuel consumption and cargo weight
                auto csumfuel       = cryptoContext->EvalSum(data.fuelConsumption, numSlots);
                auto csumweight     = cryptoContext->EvalSum(data.cargoWeight, numSlots);
                auto cmeanfuel      = cryptoContext->EvalMult(0.03125, csumfuel);       // 1/32 = 0,03125
                auto cmeanweight    = cryptoContext->EvalMult(0.03125, csumweight);     // 1/32 = 0,03125
                bm_results.PCor_Calc_DurCalcMean += TOC_US(tmean) / 1000.0;

                // numerator: sum((x_i - x_avg)*(y_i - y_avg))
                auto cxixavg = cryptoContext->EvalSub(data.fuelConsumption, cmeanfuel);
                auto cyiyavg = cryptoContext->EvalSub(data.cargoWeight, cmeanweight);
                auto numerator = cryptoContext->EvalSum(cryptoContext->EvalMult(cxixavg, cyiyavg), numSlots);

                // denominator: sqrt(sum((x_i - x_avg)²) * sum((y_i - y_avg)²))
                TIC(tsq);
                auto denom1 = cryptoContext->EvalSum(cryptoContext->EvalSquare(cxixavg), numSlots);
                auto denom2 = cryptoContext->EvalSum(cryptoContext->EvalSquare(cyiyavg), numSlots);
                auto denom3 = cryptoContext->EvalMult(denom1,denom2);
                bm_results.PCor_Calc_DurCalcSq += TOC_US(tsq) / 1000.0;
                TIC(trsq);
                double lowerBound = 5e6;
                double upperBound = 16e6;
                uint32_t polydeg = 150;
               // denom3 = Bootstrap(denom3);



                auto denom4    = cryptoContext->EvalChebyshevFunction([](double x) -> double { return std::sqrt(x); }, denom3, lowerBound, upperBound, polydeg); // root square
                bm_results.PCor_Calc_DurCalcRSq += TOC_US(trsq) / 1000.0;
                //denom4 = Bootstrap(denom4);
                TIC(tdiv);
                auto denominator = cryptoContext->EvalDivide(denom4, std::sqrt(lowerBound), std::sqrt(upperBound), polydeg);
                auto result = cryptoContext->EvalMult(numerator, denominator);
                bm_results.PCor_Calc_DurCalcDiv += TOC_US(tdiv) / 1000.0;




                pcorresults.push_back(result);
                

                // Just for debugging
                // DecryptSingleCipher("Fuel Consumption: ", data.fuelConsumption);
                // DecryptSingleCipher("Cargo Weight: ", data.cargoWeight);
                // DecryptSingleCipher("Sum of Fuel Consumption: ", csumfuel);
                // DecryptSingleCipher("Sum of Cargo Weight: ", csumweight);
                // DecryptSingleCipher("Mean of Fuel Consumption: ", cmeanfuel);
                // DecryptSingleCipher("Mean of Cargo Weight: ", cmeanweight);
                // DecryptSingleCipher("cxixavg: ", cxixavg);
                // DecryptSingleCipher("cyiyavg: ", cyiyavg);
                // DecryptSingleCipher("Numerator: ", numerator);
                // DecryptSingleCipher("denom1: ", denom1);
                // DecryptSingleCipher("denom2: ", denom2);
                // DecryptSingleCipher("Denominator before root square: ", denom3);
                // DecryptSingleCipher("Denominator after root square: ", denom4);
                // DecryptSingleCipher("Denominator (1/x): ", denominator);
                // DecryptSingleCipher("Pearson Correlation Coefficient: ", result);
            }

            bm_results.PCor_Calc_Dur = TOC_US(t) / 1000.0;
            bm_results.PCor_Calc_LvlAfter = pcorresults[0]->GetLevel();

            std::cout << "Level after Pearson Correlation: " << pcorresults[0]->GetLevel();

            //==============================================================
            // BOOTSTRAPPING
            //==============================================================
            // some modifications have been made in ckksrns-fhe.cpp in order to get 
            // a console output of bootstrapping timings.
            // The console output is redirected into a stringstream,
            // bootstrapping timings are extracted and then the
            // output is redirected to console again.
            
            TimeVar t_bs1;
            TIC(t_bs1);  //Start timer for first bootstrapping

            for(size_t i =0; i < pcorresults.size(); i++){
                std::stringstream output; // stream for output of openFHE lib
                std::streambuf* old_cout = std::cout.rdbuf(output.rdbuf()); //redirection of std::cout

                PCorResult.push_back(cryptoContext->EvalBootstrap(pcorresults[i], 1U, 0U));
                std::cout.rdbuf(old_cout); // reset of std::cout
                std::vector<double> bstimings = stringToDoubleVector(output.str());

                bm_results.PCor_BS_DurRaiseMod      += bstimings[0];
                bm_results.PCor_BS_DurCoeffsToSlot  += bstimings[1];
                bm_results.PCor_BS_DurSine          += bstimings[2];
                bm_results.PCor_BS_DurSlotsToCoeff  += bstimings[3];

            }
            
            // bm_results.ErrorAfterBS1 = precision;
            bm_results.PCor_BS_LvlAfter = PCorResult[0]->GetLevel();
            bm_results.PCor_BS_Dur = TOC(t_bs1);

            //==============================================================
            // DECRYPTION
            //==============================================================

            try
            {
                // Decrypt the encrypted result
                std::vector<double> results, resultsbs;

                for(size_t i = 0; i < pcorresults.size(); i++)
                {
                    Plaintext resultPCor, resultPCorBS;
                    cryptoContext->Decrypt(keyPair.secretKey, pcorresults[i], &resultPCor);
                    resultPCor->SetLength(numSlots);

                    cryptoContext->Decrypt(keyPair.secretKey, PCorResult[i], &resultPCorBS);
                    resultPCorBS->SetLength(numSlots);

                    results.push_back(resultPCorBS->GetRealPackedValue()[0]);     //All elements of plaintext are equal therefore its sufficent to read first element
                    resultsbs.push_back(resultPCorBS->GetRealPackedValue()[0]);
                }
                
                // Record the duration of the Pearson correlation calculation
                bm_results.PCor_Dur = TOC_US(t) / 1000.0;
                // Record the precision of the Pearson correlation result
                bm_results.PCor_Calc_PrecAfter = std::floor(CalculateApproximationError(RawPCor, results));
                bm_results.PCor_BS_PrecAfter = std::floor(CalculateApproximationError(RawPCor, resultsbs));
                bm_results.PCor_ResExp = vectorToFormattedString(RawPCor, RawPCor.size());
                bm_results.PCor_ResAct = vectorToFormattedString(resultsbs, resultsbs.size());

                // Print the results of the Pearson correlation 
                std::cout << "\nResults of Pearson correlation" << std::endl;
                printVector("\tExpected result:\t", RawPCor, RawPCor.size());
                printVector("\tActual result:\t\t", resultsbs, resultsbs.size());
                std::cout << "\tPrecision: " << bm_results.PCor_BS_PrecAfter << " bits" << std::endl;
            
            }
            catch(const std::exception& e)
            {
                // Handle decryption errors
                bm_results.Comment = "Error while decrypting Pearson correlation coefficients results";
                std::cerr << e.what() << '\n';
            }

        }

        /**
         * @brief Calculates the encrypted variance of input values.
         */
        void CalcCipherVar(){
            TimeVar t, tmean, tsub, tsquare; // Timer variable to measure execution time
            TIC(t); // Start the timer

            //==============================================================
            // CALCULATION
            //==============================================================

            std::cout << "\nStart of variance calculation" << std::endl; // Print a message indicating the start of the variance calculation
            std::vector<Ciphertext<DCRTPoly>> varresults;
            bm_results.Var_Calc_LvlBefore = CipherInput[0].fuelConsumption->GetLevel();
            std::cout << "\tLevel before variance calculation: " << CipherInput[0].fuelConsumption->GetLevel() << std::endl;

             TIC(t); 
            for (const auto& [truckId, data] : CipherInput) {
                TIC(tmean);
                // calculate mean value
                auto csum = cryptoContext->EvalSum(data.fuelConsumption, numSlots);
                auto cmean = cryptoContext->EvalMult(0.03125, csum);   // 1/32 = 0,03125
                bm_results.Var_Calc_DurCalcMean += TOC_US(tmean)/ 1000;

                 // Calculate the squared differences between fuel consumption and the mean
                 TIC(tsub);
                 auto cdiff = cryptoContext->EvalSub(data.fuelConsumption, cmean);
                 bm_results.Var_Calc_DurCalcSub += TOC_US(tsub) / 1000.0;
                 TIC(tsquare);
                 auto csq = cryptoContext->EvalSquare(cdiff);
                 bm_results.Var_Calc_DurCalcSq += TOC_US(tsquare) / 1000.0;

                 // Sum all squared differences and divide it by number of values (32)
                 auto csum2 = cryptoContext->EvalSum(csq, numSlots);
                 auto cresult = cryptoContext->EvalMult(0.03125, csum2);   // 1/32 = 0,03125
            
                varresults.push_back(cresult);
            }

            bm_results.Var_Calc_Dur = TOC_US(t) / 1000.0;
            bm_results.Var_Calc_LvlAfter = varresults[0]->GetLevel();

            std::cout << "Level after variance calculation: " << varresults[0]->GetLevel();

            //==============================================================
            // BOOTSTRAPPING
            //==============================================================
            // some modifications have been made in ckksrns-fhe.cpp in order to get 
            // a console output of bootstrapping timings.
            // The console output is redirected into a stringstream,
            // bootstrapping timings are extracted and then the
            // output is redirected to console again.
            
            TimeVar t_bs1;
            TIC(t_bs1);  //Start timer for first bootstrapping

            for(size_t i =0; i < varresults.size(); i++){
                std::stringstream output; // stream for output of openFHE lib
                std::streambuf* old_cout = std::cout.rdbuf(output.rdbuf()); //redirection of std::cout

                VarResult.push_back(cryptoContext->EvalBootstrap(varresults[i], 1U, 0U));
                std::cout.rdbuf(old_cout); // reset of std::cout
                std::vector<double> bstimings = stringToDoubleVector(output.str());

                bm_results.Var_BS_DurRaiseMod      += bstimings[0];
                bm_results.Var_BS_DurCoeffsToSlot  += bstimings[1];
                bm_results.Var_BS_DurSine          += bstimings[2];
                bm_results.Var_BS_DurSlotsToCoeff  += bstimings[3];

            }
            
            // bm_results.ErrorAfterBS1 = precision;
            bm_results.Var_BS_LvlAfter = VarResult[0]->GetLevel();
            bm_results.Var_BS_Dur = TOC(t_bs1);

            //==============================================================
            // DECRYPTION
            //==============================================================

            try
            {
                // Decrypt the encrypted result
                std::vector<double> results, resultsbs;

                for(size_t i = 0; i < varresults.size(); i++)
                {
                    Plaintext resultPCor, resultPCorBS;
                    cryptoContext->Decrypt(keyPair.secretKey, varresults[i], &resultPCor);
                    resultPCor->SetLength(numSlots);

                    cryptoContext->Decrypt(keyPair.secretKey, VarResult[i], &resultPCorBS);
                    resultPCorBS->SetLength(numSlots);

                    results.push_back(resultPCorBS->GetRealPackedValue()[0]);     //All elements of plaintext are equal therefore its sufficent to read first element
                    resultsbs.push_back(resultPCorBS->GetRealPackedValue()[0]);
                }
                
                // Record the duration of the variance calculation
                bm_results.Var_Dur = TOC_US(t) / 1000.0;
                // Record the precision of the variance result
                bm_results.Var_Calc_PrecAfter = std::floor(CalculateApproximationError(RawVar, results));
                bm_results.Var_BS_PrecAfter = std::floor(CalculateApproximationError(RawVar, resultsbs));
                bm_results.Var_ResExp = vectorToFormattedString(RawVar, RawVar.size());
                bm_results.Var_ResAct = vectorToFormattedString(resultsbs, resultsbs.size());

                // Print the results of the variance calculation
                std::cout << "\nResults of variance calculation" << std::endl;
                printVector("\tExpected result:\t", RawVar, RawVar.size());
                printVector("\tActual result:\t\t", resultsbs, resultsbs.size());
                std::cout << "\tPrecision: " << bm_results.Var_BS_PrecAfter << " bits" << std::endl;
            
            }
            catch(const std::exception& e)
            {
                // Handle decryption errors
                bm_results.Comment = "Error while decrypting variance results";
                std::cerr << e.what() << '\n';
            }
            
        }

        /**
         * @brief Calculates the encrypted variance of input values.
         */
        void CalcCipherSDev(){
            TimeVar t, tmean, tsub, tsquare; // Timer variable to measure execution time
            TIC(t); // Start the timer

            //==============================================================
            // CALCULATION
            //==============================================================

            std::cout << "\nStart of standard deviation calculation" << std::endl; // Print a message indicating the start of the standard deviation calculation
            std::vector<Ciphertext<DCRTPoly>> sdevresults;
            bm_results.SDev_Calc_LvlBefore = CipherInput[0].fuelConsumption->GetLevel();
            std::cout << "\tLevel before standard deviation calculation: " << CipherInput[0].fuelConsumption->GetLevel() << std::endl;

            TIC(tmean);
            for (const auto& [truckId, data] : CipherInput) {
                // calculate mean value
                auto csum = cryptoContext->EvalSum(data.fuelConsumption, numSlots);
                auto cmean = cryptoContext->EvalMult(0.03125, csum);   // 1/32 = 0,03125
                bm_results.SDev_Calc_DurCalcMean += TOC_US(tmean) / 1000;

                 // Calculate the squared differences between fuel consumption and the mean
                 TIC(tsub);
                 auto cdiff = cryptoContext->EvalSub(data.fuelConsumption, cmean);
                 bm_results.SDev_Calc_DurCalcSub += TOC_US(tsub) / 1000.0;
                 TIC(tsquare);
                 auto csq = cryptoContext->EvalSquare(cdiff);
                 bm_results.SDev_Calc_DurCalcSq += TOC_US(tsquare) / 1000.0;

                 // Sum all squared differences and divide it by number of values (32)
                 auto csum2 = cryptoContext->EvalSum(csq, numSlots);
                 auto cresult = cryptoContext->EvalMult(0.03125, csum2);   // 1/32 = 0,03125

                 //DecryptSingleCipher("Vector before root square: ", cresult);

                 cresult  = cryptoContext->EvalChebyshevFunction([](double x) -> double { return std::sqrt(x); }, cresult, 60, 130, 150); // root square
                TIC(tmean);
                sdevresults.push_back(cresult);
            }

            bm_results.SDev_Calc_Dur = TOC_US(t) / 1000.0;
            bm_results.SDev_Calc_LvlAfter = sdevresults[0]->GetLevel();

            std::cout << "Level after standard deviation calculation: " << sdevresults[0]->GetLevel();

            //==============================================================
            // BOOTSTRAPPING
            //==============================================================
            // some modifications have been made in ckksrns-fhe.cpp in order to get 
            // a console output of bootstrapping timings.
            // The console output is redirected into a stringstream,
            // bootstrapping timings are extracted and then the
            // output is redirected to console again.
            
            TimeVar t_bs1;
            TIC(t_bs1);  //Start timer for first bootstrapping

            for(size_t i =0; i < sdevresults.size(); i++){
                std::stringstream output; // stream for output of openFHE lib
                std::streambuf* old_cout = std::cout.rdbuf(output.rdbuf()); //redirection of std::cout

                SDevResult.push_back(cryptoContext->EvalBootstrap(sdevresults[i], 1U, 0U));
                std::cout.rdbuf(old_cout); // reset of std::cout
                std::vector<double> bstimings = stringToDoubleVector(output.str());

                bm_results.SDev_BS_DurRaiseMod      += bstimings[0];
                bm_results.SDev_BS_DurCoeffsToSlot  += bstimings[1];
                bm_results.SDev_BS_DurSine          += bstimings[2];
                bm_results.SDev_BS_DurSlotsToCoeff  += bstimings[3];

            }
            
            bm_results.SDev_BS_LvlAfter = SDevResult[0]->GetLevel();
            bm_results.SDev_BS_Dur = TOC(t_bs1);

            //==============================================================
            // DECRYPTION
            //==============================================================

            try
            {
                // Decrypt the encrypted result
                std::vector<double> results, resultsbs;

                for(size_t i = 0; i < sdevresults.size(); i++)
                {
                    Plaintext resultSDev, resultSDevBS;
                    cryptoContext->Decrypt(keyPair.secretKey, sdevresults[i], &resultSDev);
                    resultSDev->SetLength(numSlots);

                    cryptoContext->Decrypt(keyPair.secretKey, SDevResult[i], &resultSDevBS);
                    resultSDevBS->SetLength(numSlots);

                    results.push_back(resultSDevBS->GetRealPackedValue()[0]);     //All elements of plaintext are equal therefore its sufficent to read first element
                    resultsbs.push_back(resultSDevBS->GetRealPackedValue()[0]);
                }
                
                // Record the duration of the standard deviation calculation
                bm_results.SDev_Dur = TOC_US(t) / 1000.0;
                // Record the precision of the standard deviation result
                bm_results.SDev_Calc_PrecAfter = std::floor(CalculateApproximationError(RawSDev, results));
                bm_results.SDev_BS_PrecAfter = std::floor(CalculateApproximationError(RawSDev, resultsbs));
                bm_results.SDev_ResExp = vectorToFormattedString(RawSDev, RawSDev.size());
                bm_results.SDev_ResAct = vectorToFormattedString(resultsbs, resultsbs.size());

                // Print the results of the standard deviation calculation
                std::cout << "\nResults of standard deviation calculation" << std::endl;
                printVector("\tExpected result:\t", RawSDev, RawSDev.size());
                printVector("\tActual result:\t\t", resultsbs, resultsbs.size());
                std::cout << "\tPrecision: " << bm_results.SDev_BS_PrecAfter << " bits" << std::endl;
            
            }
            catch(const std::exception& e)
            {
                // Handle decryption errors
                bm_results.Comment = "Error while decrypting standard deviation results";
                std::cerr << e.what() << '\n';
            }
            
        }
            

        /**
         * @brief Calculates the throughput of several KPIs in kb/s
        */
        void CalculateThroughput(){
            
            int length = CipherInput.size();

            // Encryption throughput: amount of encrypted datasets multiplied with data size divided by duration (in seconds)
            bm_results.ThroughputEncryption = (bm_results.SizeData * length) / (static_cast<double>(bm_results.DurEncryption) / 1000);

            // Encryption throughput: amount of result ciphertexts (CO2e, mean, var) multiplied with data size divided by duration (in seconds)
            bm_results.ThroughputDecryption = (bm_results.SizeData * 4) / (static_cast<double>(bm_results.DurDecryption) / 1000);

            bm_results.CO2e_BS_Throughput = (bm_results.SizeData / static_cast<double>(bm_results.CO2e_BS_Dur) / 1000);
            bm_results.PCor_BS_Throughput = (bm_results.SizeData / static_cast<double>(bm_results.PCor_BS_Dur) / 1000);
            bm_results.Var_BS_Throughput  = (bm_results.SizeData / static_cast<double>(bm_results.Var_BS_Dur) / 1000);
            bm_results.SDev_BS_Throughput = (bm_results.SizeData / static_cast<double>(bm_results.SDev_BS_Dur) / 1000);

        }

        /**
         * @brief Handles json file. Creating a new one if file doesn't exist.
         * Otherwise, it appends the current result to the file.
         */
        void WriteJSON(double OverallDuration, std::string filename){
            //Add overall duration to result file
            bm_results.DurOverall = OverallDuration;
            std::cout << "\nOverall duration: " << OverallDuration << " ms" << std::endl;

            Json::Value root;
            std::ifstream inputFile(filename);
            if (inputFile.is_open()) {
                inputFile >> root;
                inputFile.close();
            } else {
                root = Json::Value(Json::arrayValue); 
                std::cout << "No JSON file fount. Creating a new one" << std::endl;
            }

            // new json object with current results
            Json::Value newResult;
            newResult["Batchsize"]                  = bm_results.Batchsize;
            newResult["CO2e_Dur"]                   = bm_results.CO2e_Dur;
            newResult["CO2e_BS_Dur"]                = bm_results.CO2e_BS_Dur;
            newResult["CO2e_BS_DurCoeffsToSlot"]    = bm_results.CO2e_BS_DurCoeffsToSlot;
            newResult["CO2e_BS_DurRaiseMod"]        = bm_results.CO2e_BS_DurRaiseMod;
            newResult["CO2e_BS_DurSine"]            = bm_results.CO2e_BS_DurSine;
            newResult["CO2e_BS_DurSlotsToCoeff"]    = bm_results.CO2e_BS_DurSlotsToCoeff;
            newResult["CO2e_BS_LvlAfter"]           = bm_results.CO2e_BS_LvlAfter;
            newResult["CO2e_BS_PrecAfter"]          = bm_results.CO2e_BS_PrecAfter;
            newResult["CO2e_Calc_Dur"]              = bm_results.CO2e_Calc_Dur;
            newResult["CO2e_Calc_DurCalcMult"]      = bm_results.CO2e_Calc_DurCalcMult;
            newResult["CO2e_Calc_LvlAfter"]         = bm_results.CO2e_Calc_LvlAfter;
            newResult["CO2e_Calc_LvlBefore"]        = bm_results.CO2e_Calc_LvlBefore;
            newResult["CO2e_Calc_PrecAfter"]        = bm_results.CO2e_Calc_PrecAfter;
            newResult["CO2e_ResAct"]                = bm_results.CO2e_ResAct;
            newResult["CO2e_ResExp"]                = bm_results.CO2e_ResExp;
            newResult["Comment"]                    = bm_results.Comment;
            newResult["DurDecryption"]              = bm_results.DurDecryption;
            newResult["DurOverall"]                 = bm_results.DurOverall;
            newResult["DurEncoding"]                = bm_results.DurEncoding;
            newResult["DurEncryption"]              = bm_results.DurEncryption;
            newResult["FirstModSize"]               = bm_results.FirstModSize;
            newResult["Log2(q) [-]"]               = bm_results.Log2q;
            newResult["LevelAfterBootstrapping"]    = bm_results.LevelAfterBootstrapping;
            newResult["LevelBudget"]                = bm_results.LevelBudget;
            newResult["MultiplicativeDepth"]        = bm_results.MultiplicativeDepth;
            newResult["PCor_Dur"]                   = bm_results.PCor_Dur;
            newResult["PCor_BS_LvlAfter"]           = bm_results.PCor_BS_LvlAfter;
            newResult["PCor_BS_PrecAfter"]          = bm_results.PCor_BS_PrecAfter;
            newResult["PCor_BS_Dur"]                = bm_results.PCor_BS_Dur;
            newResult["PCor_Calc_Dur"]              = bm_results.PCor_Calc_Dur;            
            newResult["PCor_Calc_DurCalcMean"]      = bm_results.PCor_Calc_DurCalcMean;
            newResult["PCor_Calc_DurCalcSq"]        = bm_results.PCor_Calc_DurCalcSq;
            newResult["PCor_Calc_DurCalcDiv"]       = bm_results.PCor_Calc_DurCalcDiv;
            newResult["PCor_Calc_DurCalcRSq"]       = bm_results.PCor_Calc_DurCalcRSq;
            newResult["PCor_Calc_LvlAfter"]         = bm_results.PCor_Calc_LvlAfter;
            newResult["Pcor_ResAct"]                = bm_results.PCor_ResAct;
            newResult["PCor_ResExp"]                = bm_results.PCor_ResExp;
            newResult["RingDimension"]              = bm_results.RingDimension;
            newResult["ScaleModSize"]               = bm_results.ScaleModSize;
            newResult["ScalingTechnique"]           = bm_results.ScalingTechnique;
            newResult["SDev_Dur"]                   = bm_results.SDev_Dur;
            newResult["SDev_BS_LvlAfter"]           = bm_results.SDev_BS_LvlAfter;
            newResult["SDev_BS_PrecAfter"]          = bm_results.SDev_BS_PrecAfter;
            newResult["SDev_BS_Dur"]                = bm_results.SDev_BS_Dur;
            newResult["SDev_Calc_Dur"]              = bm_results.SDev_Calc_Dur;
            newResult["SDev_Calc_DurCalcMean"]       = bm_results.SDev_Calc_DurCalcMean;
            newResult["SDev_Calc_DurCalcSq"]        = bm_results.SDev_Calc_DurCalcSq;
            newResult["SDev_Calc_DurCalcSub"]       = bm_results.SDev_Calc_DurCalcSub;
            newResult["SDev_Calc_LvlAfter"]         = bm_results.SDev_Calc_LvlAfter;
            newResult["SDev_ResAct"]                = bm_results.SDev_ResAct;
            newResult["SDev_ResExp"]                = bm_results.SDev_ResExp;
            newResult["SizeCryptoContext"]          = bm_results.SizeCryptoContext;
            newResult["SizeData"]                   = bm_results.SizeData;
            newResult["SizeEvalMultKey"]            = bm_results.SizeEvalMultKey;
            newResult["SizeRotKey"]                 = bm_results.SizeRotKey;
            newResult["ThroughputDecryption"]       = bm_results.ThroughputDecryption;
            newResult["ThroughputEncryption"]       = bm_results.ThroughputEncryption;
            newResult["Var_BS_LvlAfter"]            = bm_results.Var_BS_LvlAfter;
            newResult["Var_BS_PrecAfter"]           = bm_results.Var_BS_PrecAfter;            
            newResult["Var_Dur"]                    = bm_results.Var_Dur;            
            newResult["Var_BS_Dur"]                 = bm_results.Var_BS_Dur;                        
            newResult["Var_BS_DurCoeffsToSlot"]     = bm_results.Var_BS_DurCoeffsToSlot;            
            newResult["Var_BS_DurRaiseMod"]         = bm_results.Var_BS_DurRaiseMod;                        
            newResult["Var_BS_DurSine"]             = bm_results.Var_BS_DurSine;                        
            newResult["Var_BS_DurSlotsToCoeff"]     = bm_results.Var_BS_DurSlotsToCoeff;
            newResult["Var_Calc_Dur"]               = bm_results.Var_Calc_Dur;
            newResult["Var_Calc_DurCalcMean"]       = bm_results.Var_Calc_DurCalcMean;
            newResult["Var_Calc_DurCalcSq"]         = bm_results.Var_Calc_DurCalcSq;
            newResult["Var_Calc_DurCalcSub"]        = bm_results.Var_Calc_DurCalcSub;
            newResult["Var_Calc_LvlAfter"]          = bm_results.Var_Calc_LvlAfter;
            newResult["Var_ResAct"]                 = bm_results.Var_ResAct;
            newResult["Var_ResExp"]                 = bm_results.Var_ResExp;
            newResult["TimeStamp"]                  = bm_results.TimeStamp;


            root.append(newResult);

            // write json file
            std::ofstream outputFile(filename);
            if (outputFile.is_open()) {
                outputFile << root;
                outputFile.close();
                std::cout << "Results appended to JSON file." << std::endl;
            } else {
                std::cerr << "Error while writing JSON file." << std::endl;
            }
        }

        void ClearFHE(){
            cryptoContext->ClearEvalMultKeys();
            cryptoContext->ClearEvalAutomorphismKeys();
            lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
        }
};

void Benchmark(const std::string& filename, int repetitions, int rescaletech, int batchsize, int scalemodsize, int firstmodsize, int ringdim, int deslvl, usint lvlbudget){
    
    for(int i=0; i < repetitions; i++){
        TimeVar t;

        std::cout << "\n====== Benchmark (" << rescaletech << "/" << batchsize << "/" << scalemodsize << "/" << firstmodsize << "/" << ringdim << "/" << deslvl << "/" << lvlbudget  << ") =====" << std::endl;
        std::cout << "       Repetition " << i+1 << "/" << repetitions << std::endl;
        TIC(t);
        FHEBenchmark bm(rescaletech, batchsize, scalemodsize, firstmodsize, ringdim, deslvl, lvlbudget);
        bm.EncryptData();
        bm.SetDataSize();
        bm.CalcCipherCO2e();
        bm.CalcCipherPearsonCorr();
        bm.CalcCipherVar();
        bm.CalcCipherSDev();
        bm.Decrypt();
        bm.CalculateThroughput();
        bm.WriteJSON(TOC(t), filename);
        bm.ClearFHE();
    }
}

int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <Filename.json> <Repetitions>" << std::endl;
        return 1;
    }

    // save parameters to variabels
    std::string Filename = argv[1];
    int Repetitions = std::atoi(argv[2]); // std::atoi casts string to int

    // check if repetions is a positive integer
    if (Repetitions <= 0) {
        std::cerr << "Reptitions must be a positive integer" << std::endl;
        return 1;
    }

    // Read fleet data from json file and make it available as global variable
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::ifstream file("FleetData.json");
    std::string errors;

    if (!Json::parseFromStream(builder, file, &root, &errors)) {
        std::cout << "Error while parsing json file: " << errors << std::endl;
    }

    // extract data
    for (const auto& entry : root) {
        int truckId = entry["TruckID"].asInt();
        FleetData& data = fleetMap[truckId];
        data.driverIDs.push_back(entry["DriverID"].asDouble());
        data.locLat.push_back(entry["LocLat"].asDouble());
        data.locLong.push_back(entry["LocLong"].asDouble());
        data.distanceTravelled.push_back(entry["DistanceTravelled"].asDouble());
        data.co2Emissions.push_back(entry["CO2Emissions"].asDouble());
        data.emissionFactor.push_back(entry["EmssionFactor"].asDouble());
        data.speed.push_back(entry["Speed"].asDouble());
        data.fuelConsumption.push_back(entry["FuelConsumption"].asDouble());
        data.cargoWeight.push_back(entry["CargoWeight"].asDouble());
    }

    ////////////////////////////////////////////////////////////////
    // BENCHMARKING
    ////////////////////////////////////////////////////////////////

    TimeVar t;
    TIC(t);  //Start timer

    int i = 1;

    for (int j = 1; j <= 3; ++j) { // Rescale technique from 1 to 3
        //for (int k : {32, 64, 128}) { // batchsize: 8, 16, 32, 64, 128
      
            for (auto pair : {std::make_pair(59, 60)})  { //ScaleModSize and FirstModSize: (49, 50), (54, 55), (59, 60)
                for (int l : {1024}) { // ring dimensionr:  1024,2048,4096,8192,16384
                    for (int h : {22, 25}){
                        for (int o: {1,2}){
                            std::cout << "##############################" << std::endl;
                            std::cout << "  Benchmark no " << i++ << "/" << 270 << std::endl;
                            std::cout << "##############################" << std::endl;
                            Benchmark(Filename, Repetitions, j, 32, pair.first, pair.second, l, h, o);

                        }
                    }
                }
            }
        //}
    }

    int seconds = TOC(t) / 1000;            // ms --> s
    int hours = seconds / 3600;             // s --> h
    int remainingSeconds = seconds % 3600;  // remaining secods after conversion into hours
    int minutes = remainingSeconds / 60;    // s --> min

    std::cout << "\n Benchmarking completed in " << hours << " hours and " << minutes << " minutes." << std::endl;
        
}