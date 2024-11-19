export default function LoadingAnimation() {
    return (
        <div className="flex justify-center items-center my-8">
            <div className="animate-spin rounded-full h-32 w-32 border-t-2 border-b-2 border-blue-500"></div>
            <span className="ml-4 text-lg text-gray-600 dark:text-gray-300">Auditing contract...</span>
        </div>
    )
}
